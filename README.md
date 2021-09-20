### Required configurations at:

* *config/app.yml* 
* *config/casbin_model.conf*


> *go run -race main.go [-cpath=my/custom/config/path]*

### TODO

- [ ] Add migration to automatically create default set of roles/permissions

```postgresql
INSERT INTO casbin_rule(ptype, v0, v1, v2) VALUES('p', 'user', 'res', 'read');
INSERT INTO casbin_rule(ptype, v0, v1, v2) VALUES('p', 'user', 'res', 'write');
INSERT INTO casbin_rule(ptype, v0, v1, v2) VALUES('p', 'user', 'res', 'delete');
INSERT INTO casbin_rule(ptype, v0, v1) VALUES('g', 'admin', 'user');
INSERT INTO casbin_rule(ptype, v0, v1, v2) VALUES('p', 'admin', 'usr', 'read');

INSERT INTO casbin_rule(ptype, v0, v1) VALUES('g', '1', 'admin');
```
* [ ] Get rid of gin dependency
* [ ] Make *auth.User pluggable/customizable/expandable
* [ ] Logout per instance (access_token/refresh_token pair) + logout from all instances