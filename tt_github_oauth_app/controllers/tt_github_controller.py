import json
import logging

import werkzeug
from odoo.addons.auth_oauth.controllers.main import OAuthLogin, OAuthController, fragment_to_query_string
from odoo.addons.auth_signup.controllers.main import AuthSignupHome as Home
from odoo.addons.web.controllers.utils import ensure_db, _get_login_redirect_url
from werkzeug.exceptions import BadRequest

from odoo import http, api, SUPERUSER_ID, _
from odoo import registry as registry_get
from odoo.exceptions import AccessDenied
from odoo.http import request

_logger = logging.getLogger(__name__)


class TTAuthLoginHome(Home):
    @http.route()
    def web_login(self, *args, **kw):
        ensure_db()
        if request.httprequest.method == 'GET' and request.session.uid and request.params.get('redirect'):
            return request.redirect(request.params.get('redirect'))
        tt_providers = self.list_providers()

        response = super(OAuthLogin, self).web_login(*args, **kw)
        if response.is_qweb:
            error = request.params.get('oauth_error')
            if error == '1':
                error = _("You are not allowed to signup on this database.")
            elif error == '2':
                error = _("Access Denied")
            elif error == '3':
                error = _("Email Already Exist.\nPlease contact your Administrator.")
            elif error == '4':
                error = _("Validation End Point either Not present or invalid.\nPlease contact your Administrator")
            elif error == '5':
                error = _("Github Oauth Api Failed, For more information please contact Administrator")
            elif error == '6':
                error = _("Github Oauth Api Failed,\nClient ID or Client Secret Not present or has been compromised\n"
                          "For more information please contact Administrator")
            else:
                error = None
            response.qcontext['providers'] = tt_providers
            if error:
                response.qcontext['error'] = error

        return response


class TTGitHubOAuthController(OAuthController):

    @http.route('/tt/auth_oauth/signin', type='http', auth='none')
    @fragment_to_query_string
    def tt_signin(self, **kw):
        tt_state = json.loads(kw['state'])
        tt_dbname = tt_state['d']
        if not http.db_filter([tt_dbname]):
            return BadRequest()
        tt_provider = tt_state['p']
        tt_context = tt_state.get('c', {})
        tt_registry = registry_get(tt_dbname)
        with tt_registry.cursor() as cr:
            try:
                tt_context.update({'tt_provider': tt_provider, 'github': True})
                env = api.Environment(cr, SUPERUSER_ID, tt_context)
                db, login, key = env['res.users'].sudo().auth_oauth(tt_provider, kw)
                cr.commit()
                tt_action = tt_state.get('a')
                tt_menu = tt_state.get('m')
                redirect = werkzeug.urls.url_unquote_plus(tt_state['r']) if tt_state.get('r') else False
                url = '/web'
                # Since /web is hardcoded, verify user has right to land on it
                if redirect:
                    url = redirect
                elif tt_action:
                    url = '/web#action=%s' % tt_action
                elif tt_menu:
                    url = '/web#menu_id=%s' % tt_menu
                pre_uid = request.session.authenticate(db, login, key)
                resp = request.redirect(_get_login_redirect_url(pre_uid, url), 303)
                resp.autocorrect_location_header = False

                # Since /web is hardcoded, verify user has right to land on it
                if werkzeug.urls.url_parse(resp.location).path == '/web' and not request.env.user._is_internal():
                    resp.location = '/'
                return resp
            except AttributeError:
                # auth_signup is not installed
                _logger.error("auth_signup not installed on database %s: oauth sign up cancelled." % (tt_dbname,))
                url = "/web/login?oauth_error=1"
            except AccessDenied:
                # oauth credentials not valid, user could be on a temporary session
                _logger.info('OAuth2: access denied, redirect to main page in case a valid session exists,\n'
                             'without setting cookies')
                url = "/web/login?oauth_error=3"
                redirect = request.redirect(url, 303)
                redirect.autocorrect_location_header = False
                return redirect
            except Exception as e:
                # signup error
                _logger.exception("OAuth2: %s" % str(e))
                url = "/web/login?oauth_error=2"

        redirect = request.redirect(url, 303)
        redirect.autocorrect_location_header = False
        return redirect


class TTOAuthLogin(OAuthLogin):

    def list_providers(self):
        try:
            tt_providers = request.env['auth.oauth.provider'].sudo().search_read([('enabled', '=', True)])
        except Exception:
            tt_providers = []
        for tt_provider in tt_providers:
            tt_state = self.get_state(tt_provider)
            if tt_provider.get('name') in ['GitHub', 'github']:
                params = dict(
                    client_id=tt_provider['client_id'],
                    scope=tt_provider['scope'],
                    state=json.dumps(tt_state),
                )
                tt_provider['auth_link'] = "%s?%s" % (tt_provider['auth_endpoint'], werkzeug.urls.url_encode(params))
            else:
                return_url = request.httprequest.url_root + 'auth_oauth/signin'
                params = dict(
                    response_type='token',
                    client_id=tt_provider['client_id'],
                    redirect_uri=return_url,
                    scope=tt_provider['scope'],
                    state=json.dumps(tt_state),
                )
                tt_provider['auth_link'] = "%s?%s" % (tt_provider['auth_endpoint'], werkzeug.urls.url_encode(params))
        return tt_providers


class TTCallbackHandler(http.Controller):

    @http.route(['/oauth/callback'], auth='public', csrf=False, methods=['GET', 'POST'], type='http')
    def get_oauth_token(self, **post):
        if post.get('state'):
            provider = request.env['auth.oauth.provider'].sudo().browse(json.loads(post.get('state')).get('p'))
        else:
            provider = request.env.ref('tt_github_oauth_app.tt_provider_github')
            provider = request.env[provider._name].sudo().browse(provider.id)
        tt_redirect_url = request.httprequest.url_root + "tt/auth_oauth/signin"
        if post.get("code"):
            client_id = provider.client_id
            client_secret = provider.tt_client_secret
            if not client_id or not client_secret:
                r_url = "/web/login?oauth_error=6"
                _logger.info(
                    'OAuth2: Either of Client ID or Client Secret not present, access denied, redirect to main page in case a valid session exists, without setting cookies')
                redirect = werkzeug.utils.redirect(r_url, 303)
                redirect.autocorrect_location_header = False
                return redirect
            else:
                tt_post_url = 'access_token=%s&state=%s&provider=%s' % (
                    post.get("code"), post.get('state'), provider.id)
                tt_redirect_url = "%s?%s" % (tt_redirect_url, tt_post_url)
                return werkzeug.utils.redirect(tt_redirect_url)
