# Ionic App Auth

Ionic AppAuth is a implementation of the [AppAuth-JS](https://github.com/openid/AppAuth-JS) for Ionic Users.
It includes code extensions for core cordova plugins to run the Ionic app such as [Advanced HTTP](https://github.com/silkimen/cordova-plugin-advanced-http) and [SafariViewController](https://github.com/EddyVerbruggen/cordova-plugin-safariviewcontroller). This is a copy from [Ionic AppAuth](https://github.com/wi3land/ionic-appauth) with hopes for better maitenance.


The cordova plugins are optional and can be replaced with Angular/React/Vue http handlers and/or Capacitor Plugins.
This library is intended to be as flexible with compatibility as Ionic v7 is attempting to be.

## Installation

Run following command to install Ionic App Auth in your project.

```bash
npm i @addahlbe/ionic-app-auth
```

## Examples

Demos have been moved into the main repository to centralise issues.
- Angular/Capacitor: https://github.com/addahlbe/ionic-app-auth/tree/master/demos/angular-capacitor<br />

**NOTE**: You can use [OktaDev Schematics](https://github.com/oktadev/schematics#ionic) to install the code from the Angular examples above. Only Capacitor is supported. The installation isn't Okta-specific, it just prompts you for an `issuer` and `clientId` and works with Auth0 too!

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* [AppAuth-JS](https://github.com/openid/AppAuth-JS)
* [AppAuth-Ionic](https://github.com/Belicosus/AppAuth-Ionic)
