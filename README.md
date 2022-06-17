### Required configurations at:

* *config/app.yml* 
* *config/casbin_model.conf*


> *go run -race main.go [-cpath=my/custom/config/path]*

### TODO

* [ ] Get rid of gin dependency
* [ ] Get rid of config.yaml file
* [ ] Make *auth.User pluggable/customizable/expandable without PostRegisterCallback()
* [ ] Logout per instance (access_token/refresh_token pair) + logout from all instances
* [ ] Add 2fa