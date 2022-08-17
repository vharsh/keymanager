\c mosip_keymgr sysadmin


ALTER TABLE keymgr.key_alias DROP COLUMN IF EXISTS uni_ident;

ALTER TABLE keymgr.key_policy_def DROP COLUMN IF EXISTS pre_expire_days;
ALTER TABLE keymgr.key_policy_def DROP COLUMN IF EXISTS access_allowed;