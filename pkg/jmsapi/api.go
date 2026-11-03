package jmsapi

// The endpoint table.
//
// This file is the only place in the repository that knows the bastion's URL
// layout. Everything above it — the tools, the policy table, the domain rules
// — asks for a RESOURCE and never spells out a path.
//
// Why a table and not a handful of one-off calls: the same endpoint is hit
// from a dozen tools (the permission list alone from nine), so a layout that
// only one place knows is a layout that can be changed in one place. Before
// this table, "/perms/asset-permissions/" appeared 25 times across the tool
// layer, and nothing but a 404 would have caught a typo in any of them.
//
// It lives in the PROTOCOL layer, not in a server, because both servers
// speak to the same bastion: the management plane lists the assets, and the
// execution plane needs the same list to tell an agent what it may log into.
// Two tables would drift.
//
// ⚠️ **Every path below is the SAME on v4 and on v5.** That was checked
// against the upstream v4.10.20-lts source — apps/jumpserver/urls.py mounts
// the same per-app prefixes, and each app's api_urls.py registers the same
// resource names — so this table is not a v5 table that happens to be
// tolerated by v4. It is the table for both. The one thing that differs
// between the versions is not a path but a scheme: v4 has no Chat AI
// delegation (see version.go).
//
// The shape of the API below is deliberately uniform — Get, List, Post,
// Patch, Delete, and the sub-resource forms. A uniform interface means the
// tool layer learns one calling convention instead of one per resource, and
// a new resource is one line of this file rather than a new method family.
//
// What does NOT live here is meaning. "Does this permission actually let
// anybody in" is a rule about the bastion's data model, not about its
// transport; that is in the management plane's biz/service, where it can be
// tested on its own.

import (
	"context"
	"net/url"
)

// Resource names a collection on the bastion.
//
// The value is the collection's endpoint, so this type IS the endpoint
// table: there is no second place that knows a URL. A tool refers to
// ResPermissions, not to "/perms/asset-permissions/".
type Resource string

// The resources.
const (
	ResAssets         Resource = "/assets/assets/"
	ResAssetHosts     Resource = "/assets/hosts/"
	ResAssetDatabases Resource = "/assets/databases/"
	ResAssetDevices   Resource = "/assets/devices/"
	ResAssetClouds    Resource = "/assets/clouds/"
	ResAssetWebs      Resource = "/assets/webs/"
	// ResZones are the network ZONES: a group of assets plus the gateways
	// that reach them. ⚠️ A zone is a field ON the asset (`zone`), so the
	// assets of a zone are read with /assets/assets/?zone=<id> -- the
	// zones collection itself only carries the zone's own record.
	ResZones Resource = "/assets/zones/"
	// ResGateways are the assets whose platform is Gateway -- the routers,
	// the jump hosts, the bastion itself.
	//
	// ⚠️ "Gateway" is a PLATFORM NAME, not a role: on this deployment the
	// seven of them include ordinary network gear (a router, a WiFi AP, an
	// nginx front end) beside the real jump hosts. ⚠️ A gateway carries a
	// `zone` field too, and a zone's `gateways` are exactly the gateways
	// whose zone is that one -- the two views are the same records.
	ResGateways       Resource = "/assets/gateways/"
	ResNodes          Resource = "/assets/nodes/"
	ResPlatforms      Resource = "/assets/platforms/"
	ResAccounts       Resource = "/accounts/accounts/"
	ResGathered       Resource = "/accounts/gathered-accounts/"
	ResGatheredStatus Resource = "/accounts/gathered-accounts/status/"
	ResGatherAdhoc    Resource = "/accounts/gather-account-executions/adhoc/"
	ResPermissions    Resource = "/perms/asset-permissions/"
	ResPermUserAssets Resource = "/perms/users/"
	ResUsers          Resource = "/users/users/"
	// ResUsersProfile answers with THE CALLER (the credential's own user
	// record) — the only route that says "who am I". Measured: 200 with the
	// caller's row on v5 (192.0.2.41) and the route present on v4
	// (192.0.2.21, 401 unauthenticated). ⚠️ Do not confuse it with
	// /users/users/profile/ or /me/: those two are absent in v5 (404).
	// ⚠️ The first row of ResUsers is NOT the caller — it is whoever the
	// list happens to order first, which is a different user whenever the
	// caller is not the admin.
	ResUsersProfile     Resource = "/users/profile/"
	ResGroups           Resource = "/users/groups/"
	ResOrgs             Resource = "/orgs/orgs/"
	ResLabels           Resource = "/labels/labels/"
	ResLabeledResources Resource = "/labels/labeled-resources/"
	ResCmdGroups        Resource = "/acls/command-groups/"
	ResCmdFilters       Resource = "/acls/command-filter-acls/"
	ResLoginACLs        Resource = "/acls/login-acls/"
	ResLoginAssetACLs   Resource = "/acls/login-asset-acls/"
	ResLoginCheck       Resource = "/acls/login-asset/check/"
	// ResDataMaskingRules and ResClipboardACLs are the other two ACL
	// families: what gets masked when a secret is shown, and what the
	// clipboard may carry. Their items' `users`/`assets` fields are
	// JSONManyToMany selectors ({"type":"all"} / {"type":"ids",...} /
	// {"type":"attrs",...}), not lists — a plain list is a 400 whose text
	// only describes the selector shape.
	ResDataMaskingRules  Resource = "/acls/data-masking-rules/"
	ResClipboardACLs     Resource = "/acls/clipboard-acls/"
	ResSessions          Resource = "/terminal/sessions/"
	ResTerminals         Resource = "/terminal/terminals/"
	ResTerminalCommands  Resource = "/terminal/commands/"
	ResJobs              Resource = "/ops/jobs/"
	ResJobExecutions     Resource = "/ops/job-executions/"
	ResJobExecutionsStop Resource = "/ops/job-executions/stop/"
	ResSSHKeys           Resource = "/authentication/ssh-key/"
	// ResConnectionToken mints the one-shot credential koko accepts as an
	// SSH login. It is listed here because it is an endpoint like any other:
	// the layer above must not spell its path out.
	ResConnectionToken Resource = "/authentication/connection-token/"
	ResOrgRoles        Resource = "/rbac/org-roles/"
	ResSystemRoles     Resource = "/rbac/system-roles/"
	ResContentTypes    Resource = "/rbac/content-types/"
	// ResRBACPermissions is the PERMISSION CATALOGUE: every permission the
	// installation defines (265 in org scope, 385 in system scope on the
	// v5 machine), each as {id, name, content_type:{app_label,model},
	// codename}. `?scope=org|system` picks the catalogue and `?role=<id>`
	// narrows it to what that role holds — which is what makes a
	// role×permission matrix cost one request per role.
	ResRBACPermissions Resource = "/rbac/permissions/"
	ResLoginLogs       Resource = "/audits/login-logs/"
	ResOperateLogs     Resource = "/audits/operate-logs/"
	ResPasswordLogs    Resource = "/audits/password-change-logs/"
	ResAuditJobs       Resource = "/audits/jobs/"
	ResAuditJobLogs    Resource = "/audits/job-logs/"
	// ResFTPLogs is the FILE TRANSFER trail: every upload and download the
	// bastion carried, with the file name, the direction and whether it
	// succeeded.
	//
	// ⚠️ It is not called "file-transfer-logs" on the wire even though the
	// model is named "File transfer log" — the collection is /audits/ftp-logs/.
	// The name is a leftover from when the bastion only did FTP; it carries
	// SFTP transfers too.
	ResFTPLogs    Resource = "/audits/ftp-logs/"
	ResBlockedIPs Resource = "/settings/security/block-ip/"

	// The ACCOUNT AUTOMATION resources: the plans and their executions.
	//
	// ⚠️ The bastion has FOUR of these families and they are NOT
	// interchangeable:
	//
	//   - PUSH   (push-account-*): the bastion generates a secret and
	//     pushes it to the target machine, keeping it in its own vault.
	//     The secret never passes through the caller. **Works on the
	//     community edition.**
	//   - GATHER (gather-account-*): the bastion logs into the machine and
	//     discovers the accounts there. Works on the community edition.
	//   - CHANGE SECRET (change-secret-*): the bastion rotates the secret
	//     of an account it already holds.
	//   - CHECK  (check-account-*): the bastion verifies that a held
	//     secret still works.
	//
	// ⚠️ The last two carry `IsValidLicense` upstream
	// (permission_classes = [RBACPermission, IsValidLicense]), so on a
	// community deployment they answer **403 permission_denied** -- which
	// reads like "you lack the permission" and is NOT: the deployment
	// simply has no licence for the feature. The read paths that DO work
	// are listed below.
	ResPushAutomations   Resource = "/accounts/push-account-automations/"
	ResPushExecutions    Resource = "/accounts/push-account-executions/"
	ResPushRecords       Resource = "/accounts/push-account-records/"
	ResGatherAutomations Resource = "/accounts/gather-account-automations/"
	ResGatherExecutions  Resource = "/accounts/gather-account-executions/"
	// ⚠️ There is NO "gather-account-records" -- upstream registers no
	// such collection, and asking for it answers 404. The gather family
	// has no per-account RESULT record: what it produces is the
	// DISCOVERED ACCOUNTS, which live in /accounts/gathered-accounts/
	// (already in this table as ResGathered, and already read by
	// jms_gathered_accounts).
)

// DelegationPath is the path a delegation credential is bound to.
//
// A delegation credential is bound to the ABSOLUTE form — the one
// request.path_info carries — so it is not the collection path the gateway
// uses. Signing the relative form made every request come back as
// "request mismatch".
func DelegationPath(res Resource) string {
	return APIPath(string(res))
}

// Get reads one item of a collection.
func (c *Client) Get(ctx context.Context, res Resource, id string, out any) error {
	return c.Do(ctx, "GET", string(res)+id+"/", nil, nil, out)
}

// GetQuery reads one item of a collection, narrowed by a query.
//
// It is the "fetch, don't page" form: a caller that wants a single row
// without walking the whole collection asks for one page of one.
func (c *Client) GetQuery(ctx context.Context, res Resource, q url.Values, out any) error {
	return c.Do(ctx, "GET", string(res), q, nil, out)
}

// List reads every row of a collection.
func (c *Client) List(ctx context.Context, res Resource) ([]map[string]any, error) {
	return c.ListAll(ctx, string(res))
}

// ListQuery reads the rows of a collection a query selects.
func (c *Client) ListQuery(ctx context.Context, res Resource, q url.Values) ([]map[string]any, error) {
	return c.ListAllQuery(ctx, string(res), q)
}

// ListSub reads the rows of a sub-resource of an item — the accounts of a
// permission, the assets of a user.
func (c *Client) ListSub(ctx context.Context, res Resource, id, sub string) ([]map[string]any, error) {
	return c.ListAll(ctx, string(res)+id+"/"+sub+"/")
}

// ListInto reads every row of a collection into the caller's slice.
//
// It is List for a caller that already has the destination — a test that
// wants to assert on the rows, or a function that hands them on.
func (c *Client) ListInto(ctx context.Context, res Resource, out *[]map[string]any) error {
	return c.ListIntoPath(ctx, string(res), out)
}

// ListSubInto reads the rows of a sub-resource into the caller's slice.
func (c *Client) ListSubInto(ctx context.Context, res Resource, id, sub string, out *[]map[string]any) error {
	return c.ListIntoPath(ctx, string(res)+id+"/"+sub+"/", out)
}

// Sub reads a sub-resource of an item.
func (c *Client) Sub(ctx context.Context, res Resource, id, sub string, out any) error {
	return c.Do(ctx, "GET", string(res)+id+"/"+sub+"/", nil, nil, out)
}

// Post adds an item to a collection, or triggers a collection-level action.
func (c *Client) Post(ctx context.Context, res Resource, body, out any) error {
	return c.Do(ctx, "POST", string(res), nil, body, out)
}

// PostSub triggers an action on an item — terminating a session, testing an
// asset's connectivity.
func (c *Client) PostSub(ctx context.Context, res Resource, id, sub string, body, out any) error {
	return c.Do(ctx, "POST", string(res)+id+"/"+sub+"/", nil, body, out)
}

// Patch changes an item.
func (c *Client) Patch(ctx context.Context, res Resource, id string, body, out any) error {
	return c.Do(ctx, "PATCH", string(res)+id+"/", nil, body, out)
}

// Put replaces a sub-resource of an item — a user's password, the assets
// filed under a node.
func (c *Client) Put(ctx context.Context, res Resource, id, sub string, body, out any) error {
	return c.Do(ctx, "PUT", string(res)+id+"/"+sub+"/", nil, body, out)
}

// PutAll replaces a whole collection-level resource.
func (c *Client) PutAll(ctx context.Context, res Resource, body, out any) error {
	return c.Do(ctx, "PUT", string(res), nil, body, out)
}

// Delete removes an item.
func (c *Client) Delete(ctx context.Context, res Resource, id string) error {
	return c.Do(ctx, "DELETE", string(res)+id+"/", nil, nil, nil)
}
