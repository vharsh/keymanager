\c mosip_keymgr sysadmin


ALTER TABLE keymgr.ca_cert_store ADD CONSTRAINT cert_thumbprint_unique UNIQUE (cert_thumbprint,partner_domain);

ALTER TABLE keymgr.key_alias ADD COLUMN uni_ident character varying(50);
ALTER TABLE keymgr.key_alias ADD CONSTRAINT uni_ident_const UNIQUE (uni_ident);

ALTER TABLE keymgr.key_policy_def ADD COLUMN pre_expire_days smallint;
ALTER TABLE keymgr.key_policy_def ADD COLUMN access_allowed character varying(1024);

-- updating default values for pre_expire_days & access_allowed columns
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='PRE_REGISTRATION';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='REGISTRATION';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='REGISTRATION_PROCESSOR';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='ID_REPO';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='KERNEL';
update keymgr.key_policy_def set pre_expire_days=1125, access_allowed='NA' where app_id='ROOT';
update keymgr.key_policy_def set pre_expire_days=30, access_allowed='NA' where app_id='BASE';
update keymgr.key_policy_def set pre_expire_days=395, access_allowed='NA' where app_id='PMS';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='RESIDENT';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='ADMIN_SERVICES';