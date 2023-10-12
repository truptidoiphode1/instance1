{
    'name': "Login via Github",
    'summary': """
                Login via Github logs user into odoo using their github credentials.
    """,
    'description': """
                    Github
                    Odoo github
                    Github login
                    Odoo Github integration
                    Github Odoo integration
                    Odoo+Github
                    Github Odoo login
                    Odoo Github authentication
                    Github login on Odoo
                    tortecs
                    tortecs_india
                    tortecs india
    """,

    'author': "Tortecs India",
    'website': "https://www.tortecs.com",
    'category': 'Technical',
    'version': '1.0.0',
    'application': True,
    'license': 'LGPL-3',
    'currency': 'EUR',
    'price': 0.0,
    'maintainer': 'Tortecs India',
    'support': 'sales@tortecs.com',
    'images': ['static/description/banner_old.gif'],
    'depends': ['auth_oauth'],
    'data': [
        'data/tt_github_auth.xml',
        'views/tt_github_oauth_providers_views.xml',
    ]
}
