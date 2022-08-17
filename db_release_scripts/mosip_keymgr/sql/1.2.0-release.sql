\c mosip_keymgr sysadmin


ALTER TABLE keymgr.key_alias ADD COLUMN cert_thumbprint character varying(100);
ALTER TABLE keymgr.ca_cert_store ADD CONSTRAINT cert_thumbprint_unique UNIQUE (cert_thumbprint,partner_domain);

ALTER TABLE keymgr.key_alias ADD COLUMN uni_ident character varying(50);
ALTER TABLE keymgr.key_alias ADD CONSTRAINT uni_ident_const UNIQUE (uni_ident);

ALTER TABLE keymgr.key_policy_def ADD COLUMN pre_expire_days smallint;
ALTER TABLE keymgr.key_policy_def ADD COLUMN access_allowed character varying(1024);

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
VALUES('DIGITAL_CARD', 1095, true, 60, 'NA', 'mosipadmin', '2022-07-12 05:40:58.155', NULL, NULL, false, NULL);

INSERT INTO keymgr.key_policy_def_h
(app_id, eff_dtimes, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
VALUES('DIGITAL_CARD', '2022-07-12 05:40:58.195', 1095, true, NULL, NULL, 'mosipadmin', '2022-07-12 05:40:58.195', NULL, NULL, false, NULL);

