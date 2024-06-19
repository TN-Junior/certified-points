# utils/components.py
'''
 from dash import html, dcc
import dash_bootstrap_components as dbc

findata = html.I("Certifications")

navbar = dbc.NavbarSimple(
    children=[
        dbc.NavItem(
            dbc.NavLink(
                dcc.Link("Logout",
                         href="/auth/logout",
                         target="_top",
                         style={"color": "white", "textDecoration": "None"})
            )
        )
    ],
    brand="Certifications",
    brand_href="/",
    brand_external_link=True,
    brand_style={"font-style": "italic"},
    color="#0f3057",
    dark=True,
)

navbar2 = dbc.Navbar(
    [
        dbc.Col([
            dbc.Row([
                html.A([
                    dbc.Row(
                        dbc.Col(
                            dbc.NavbarBrand(findata), width=2)
                    )], href="/", target="_top"
                ),
                html.A([
                    dbc.Row(
                        dbc.Col(
                            dbc.NavbarBrand("Secretaria de Finanças do Recife",
                                            style={'fontSize': '120%'}),
                            width=8)
                    )], href="/", target="_top"
                ),
            ])
        ]),
        dbc.Collapse(
            dbc.Col([
                dbc.Row([
                    dcc.Link("Logout", href="/auth/logout", target="_top",
                             style={"color": "white"})
                ], justify="end")
            ]),
            id="navbar-collapse",
            is_open=True,
        )

    ],
    id="navbar-content",
    color="#0f3057",
    dark=True,
    className="desktop-navbar",
    style={'marginBottom': 25}
)

footer = html.Footer(
    [
        dbc.Container(
            dbc.Row([
                dbc.Col([
                    dcc.Link(html.P(findata), href="/", target="_top"),
                    html.P("Sec. de Finanças do Recife")
                ]),
            ], style={'marginTop': '25px'})
        )
    ],
    id="footer-content",
    className="desktop-footer",
    style={'height': 150, 'backgroundColor': '#e7e7de',
           'display': 'flex'}
)
'''
