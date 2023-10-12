import logging

import requests
import werkzeug
from odoo.addons.auth_signup.models.res_partner import SignupError

from odoo import models, fields, api, _
from odoo.exceptions import AccessDenied
from odoo.tools.misc import ustr

_logger = logging.getLogger(__name__)


class TTResUsersInherit(models.Model):
    _inherit = 'res.users'

    oauth_token = fields.Char(string="Oauth Token", readonly=True)
    git_username = fields.Char(string="Git Username", default="No username")
    git_email = fields.Char(string="Github Email")

    def _auth_oauth_rpc(self, endpoint, access_token):
        if self.env.context.get('github'):
            provider = self.env['auth.oauth.provider'].browse(self.env.context.get('tt_provider'))
            params = {
                'client_id': provider.client_id,
                'client_secret': provider.tt_client_secret,
                'code': access_token
            }
            response = requests.get(endpoint, params=params, timeout=10)
            if response.ok:
                response_data = response.content.decode("UTF-8").split('&')
                if 'error=' in response_data or 'error=' in response_data[0]:
                    r_url = "/web/login?oauth_error=5"
                    _logger.info(
                        'OAuth2: access denied, redirect to main page in case a valid session exists, without setting cookies. REASON :- %s' % str(
                            response_data[0]))
                    redirect = werkzeug.utils.redirect(r_url, 303)
                    redirect.autocorrect_location_header = False
                    return redirect
                auth_token = response_data[0].split('=')[1]
                tt_user_data = requests.get('https://api.github.com/user', auth=('', auth_token)).json()
                params = {
                    'key': auth_token,
                    'user_id': tt_user_data.get('id'),
                    'username': tt_user_data.get('login'),
                    'name': tt_user_data.get('name'),
                    'email': tt_user_data.get('email')
                }
                return params
        else:
            if self.env['ir.config_parameter'].sudo().get_param('auth_oauth.authorization_header'):
                response = requests.get(endpoint, headers={'Authorization': 'Bearer %s' % access_token}, timeout=10)
            else:
                response = requests.get(endpoint, params={'access_token': access_token}, timeout=10)

        if response.ok:  # nb: could be a successful failure
            return response.json()

        auth_challenge = werkzeug.http.parse_www_authenticate_header(
            response.headers.get('WWW-Authenticate'))
        if auth_challenge.type == 'bearer' and 'error' in auth_challenge:
            return dict(auth_challenge)

        return {'error': 'invalid_request'}

    @api.model
    def _auth_oauth_validate(self, provider, access_token):
        """ return the validation data corresponding to the access token """
        oauth_provider = self.env['auth.oauth.provider'].browse(provider)
        validation = self._auth_oauth_rpc(oauth_provider.validation_endpoint, access_token)
        if validation.get("error"):
            raise Exception(validation['error'])
        if oauth_provider.data_endpoint:
            data = self._auth_oauth_rpc(oauth_provider.data_endpoint, access_token)
            validation.update(data)
        # unify subject key, pop all possible and get most sensible. When this
        # is reworked, BC should be dropped and only the `sub` key should be
        # used (here, in _generate_signup_values, and in _auth_oauth_signin)
        if self.env.context.get('github'):
            return validation
        subject = next(filter(None, [
            validation.pop(key, None)
            for key in [
                'sub',  # standard
                'id',  # google v1 userinfo, facebook opengraph
                'user_id',  # google tokeninfo, odoo (tokeninfo)
            ]
        ]), None)
        if not subject:
            raise AccessDenied('Missing subject identity')
        validation['user_id'] = subject

        return validation

    def tt_github_api_hit(self):
        tt_provider = self.env.ref('tt_github_oauth_app.tt_provider_github')
        tt_provider = self.env[tt_provider._name].sudo().browse(tt_provider.id)
        if tt_provider:
            if not tt_provider.client_id:
                r_url = "/web/login?oauth_error=6"
                _logger.info(
                    'OAuth2: Either of Client ID or Client Secret not present, access denied, redirect to main page in case a valid session exists, without setting cookies')
                redirect = werkzeug.utils.redirect(r_url, 303)
                redirect.autocorrect_location_header = False
                return redirect
            url = "https://github.com/login/oauth/authorize?client_id=%s&scope=repo,user" % tt_provider.client_id
            response = requests.get(url)
            if response.status_code in [200, 201]:
                return response.url

    @api.model
    def _signup_create_user(self, values):
        """ signup a new user using the template user """

        # check that uninvited users may sign up
        provider = self.env.ref('tt_github_oauth_app.tt_provider_github')
        if provider.id == values.get('oauth_provider_id') and provider.tt_user_type == 'internal':
            if 'partner_id' not in values:
                if self._get_signup_invitation_scope() != 'b2c':
                    raise SignupError(_('Signup is not allowed for uninvited users'))
            return self._tt_create_user_from_default_template(values)
        else:
            return super(TTResUsersInherit, self)._signup_create_user(values)

    def _tt_create_user_from_default_template(self, values):
        template_user = self.env.ref('base.default_user')
        if not template_user.exists():
            raise ValueError(_('Signup: invalid template user'))
        if not values.get('login'):
            raise ValueError(_('Signup: no login given for new user'))
        if not values.get('partner_id') and not values.get('name'):
            raise ValueError(_('Signup: no name or partner given for new user'))

        values['active'] = True
        try:
            with self.env.cr.savepoint():
                return template_user.with_context(no_reset_password=True).copy(values)
        except Exception as e:
            # copy may fail if asked login is not available.
            raise SignupError(ustr(e))
