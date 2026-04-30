/*
 * Copyright (C) 2011 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "xauth.h"

#include <daemon.h>
#include <string.h>
#include <arpa/inet.h>
#include <encoding/payloads/cp_payload.h>
#include <processing/jobs/adopt_children_job.h>
#include <sa/ikev1/tasks/mode_config.h>

typedef struct private_xauth_t private_xauth_t;

/**
 * Status types exchanged
 */
typedef enum {
	XAUTH_FAILED = 0,
	XAUTH_OK = 1,
} xauth_status_t;

/**
 * Private members of a xauth_t task.
 */
struct private_xauth_t {

	/**
	 * Public methods and task_t interface.
	 */
	xauth_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the XAUTH initiator?
	 */
	bool initiator;

	/**
	 * XAuth backend to use
	 */
	xauth_method_t *xauth;

	/**
	 * XAuth username
	 */
	identification_t *user;

	/**
	 * Generated configuration payload
	 */
	cp_payload_t *cp;

	/**
	 * received identifier
	 */
	uint16_t identifier;

	/**
	 * status of Xauth exchange
	 */
	xauth_status_t status;

	/**
	 * Received a non-XAUTH CFG_SET (Mode Config push), task should complete
	 * after sending the ACK.
	 */
	bool modeconfig_push_done;

	/**
	 * Queue a Mode Config Push mode after completing XAuth?
	 */
	bool mode_config_push;
};

/**
 * Load XAuth backend
 */
static xauth_method_t *load_method(private_xauth_t* this)
{
	identification_t *server, *peer;
	enumerator_t *enumerator;
	xauth_method_t *xauth;
	xauth_role_t role;
	peer_cfg_t *peer_cfg;
	auth_cfg_t *auth;
	char *name;

	if (this->initiator)
	{
		server = this->ike_sa->get_my_id(this->ike_sa);
		peer = this->ike_sa->get_other_id(this->ike_sa);
		role = XAUTH_SERVER;
	}
	else
	{
		peer = this->ike_sa->get_my_id(this->ike_sa);
		server = this->ike_sa->get_other_id(this->ike_sa);
		role = XAUTH_PEER;
	}
	peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
	enumerator = peer_cfg->create_auth_cfg_enumerator(peer_cfg, !this->initiator);
	if (!enumerator->enumerate(enumerator, &auth) ||
		(uintptr_t)auth->get(auth, AUTH_RULE_AUTH_CLASS) != AUTH_CLASS_XAUTH)
	{
		if (!enumerator->enumerate(enumerator, &auth) ||
			(uintptr_t)auth->get(auth, AUTH_RULE_AUTH_CLASS) != AUTH_CLASS_XAUTH)
		{
			DBG1(DBG_CFG, "no XAuth authentication round found");
			enumerator->destroy(enumerator);
			return NULL;
		}
	}
	name = auth->get(auth, AUTH_RULE_XAUTH_BACKEND);
	this->user = auth->get(auth, AUTH_RULE_XAUTH_IDENTITY);
	enumerator->destroy(enumerator);
	if (!this->initiator && this->user)
	{	/* use XAUTH username, if configured */
		peer = this->user;
	}
	xauth = charon->xauth->create_instance(charon->xauth, name, role,
										   server, peer);
	if (!xauth)
	{
		if (name)
		{
			DBG1(DBG_CFG, "no XAuth method found for '%s'", name);
		}
		else
		{
			DBG1(DBG_CFG, "no XAuth method found");
		}
	}
	return xauth;
}

/**
 * Check if XAuth connection is allowed to succeed
 */
static bool allowed(private_xauth_t *this)
{
	if (charon->ike_sa_manager->check_uniqueness(charon->ike_sa_manager,
												 this->ike_sa, FALSE))
	{
		DBG1(DBG_IKE, "canceling XAuth due to uniqueness policy");
		return FALSE;
	}
	if (!charon->bus->authorize(charon->bus, FALSE))
	{
		DBG1(DBG_IKE, "XAuth authorization hook forbids IKE_SA, canceling");
		return FALSE;
	}
	if (!charon->bus->authorize(charon->bus, TRUE))
	{
		DBG1(DBG_IKE, "final authorization hook forbids IKE_SA, canceling");
		return FALSE;
	}
	return TRUE;
}

/**
 * Set IKE_SA to established state
 */
static bool establish(private_xauth_t *this)
{
	DBG0(DBG_IKE, "IKE_SA %s[%d] established between %H[%Y]...%H[%Y]",
		 this->ike_sa->get_name(this->ike_sa),
		 this->ike_sa->get_unique_id(this->ike_sa),
		 this->ike_sa->get_my_host(this->ike_sa),
		 this->ike_sa->get_my_id(this->ike_sa),
		 this->ike_sa->get_other_host(this->ike_sa),
		 this->ike_sa->get_other_id(this->ike_sa));

	this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
	charon->bus->ike_updown(charon->bus, this->ike_sa, TRUE);

	return TRUE;
}

/**
 * Check if we are compliant to a given peer config
 */
static bool is_compliant(private_xauth_t *this, peer_cfg_t *peer_cfg, bool log)
{
	bool complies = TRUE;
	enumerator_t *e1, *e2;
	auth_cfg_t *c1, *c2;

	e1 = peer_cfg->create_auth_cfg_enumerator(peer_cfg, FALSE);
	e2 = this->ike_sa->create_auth_cfg_enumerator(this->ike_sa, FALSE);
	while (e1->enumerate(e1, &c1))
	{
		if (!e2->enumerate(e2, &c2) || !c2->complies(c2, c1, log))
		{
			complies = FALSE;
			break;
		}
	}
	e1->destroy(e1);
	e2->destroy(e2);

	return complies;
}

/**
 * Check if we are compliant to current config, switch to another if not
 */
static bool select_compliant_config(private_xauth_t *this)
{
	peer_cfg_t *peer_cfg = NULL, *old, *current;
	identification_t *my_id, *other_id;
	host_t *my_host, *other_host;
	enumerator_t *enumerator;
	bool aggressive;

	old = this->ike_sa->get_peer_cfg(this->ike_sa);
	if (is_compliant(this, old, TRUE))
	{	/* current config is fine */
		return TRUE;
	}
	DBG1(DBG_CFG, "selected peer config '%s' unacceptable",
		 old->get_name(old));
	aggressive = old->has_option(old, OPT_IKEV1_AGGRESSIVE);

	my_host = this->ike_sa->get_my_host(this->ike_sa);
	other_host = this->ike_sa->get_other_host(this->ike_sa);
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	enumerator = charon->backends->create_peer_cfg_enumerator(charon->backends,
								my_host, other_host, my_id, other_id, IKEV1);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (!current->equals(current, old) &&
			current->has_option(current, OPT_IKEV1_AGGRESSIVE) == aggressive &&
			is_compliant(this, current, FALSE))
		{
			peer_cfg = current;
			break;
		}
	}
	if (peer_cfg)
	{
		DBG1(DBG_CFG, "switching to peer config '%s'",
			 peer_cfg->get_name(peer_cfg));
		this->ike_sa->set_peer_cfg(this->ike_sa, peer_cfg);
	}
	else
	{
		DBG1(DBG_CFG, "no alternative config found");
	}
	enumerator->destroy(enumerator);

	return peer_cfg != NULL;
}

/**
 * Create auth config after successful authentication
 */
static bool add_auth_cfg(private_xauth_t *this, identification_t *id, bool local)
{
	auth_cfg_t *auth;

	auth = auth_cfg_create();
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_XAUTH);
	if (id)
	{
		auth->add(auth, AUTH_RULE_XAUTH_IDENTITY, id->clone(id));
	}
	auth->merge(auth, this->ike_sa->get_auth_cfg(this->ike_sa, local), FALSE);
	this->ike_sa->add_auth_cfg(this->ike_sa, local, auth);

	return select_compliant_config(this);
}

METHOD(task_t, build_i_status, status_t,
	private_xauth_t *this, message_t *message)
{
	cp_payload_t *cp;

	cp = cp_payload_create_type(PLV1_CONFIGURATION, CFG_SET);
	cp->add_attribute(cp,
			configuration_attribute_create_value(XAUTH_STATUS, this->status));

	message->add_payload(message, (payload_t *)cp);

	return NEED_MORE;
}

METHOD(task_t, process_i_status, status_t,
	private_xauth_t *this, message_t *message)
{
	cp_payload_t *cp;
	adopt_children_job_t *job;

	cp = (cp_payload_t*)message->get_payload(message, PLV1_CONFIGURATION);
	if (!cp || cp->get_type(cp) != CFG_ACK)
	{
		DBG1(DBG_IKE, "received invalid XAUTH status response");
		return FAILED;
	}
	if (this->status != XAUTH_OK)
	{
		DBG1(DBG_IKE, "destroying IKE_SA after failed XAuth authentication");
		return FAILED;
	}
	if (!establish(this))
	{
		return FAILED;
	}
	this->ike_sa->set_condition(this->ike_sa, COND_XAUTH_AUTHENTICATED, TRUE);
	job = adopt_children_job_create(this->ike_sa->get_id(this->ike_sa));
	if (this->mode_config_push)
	{
		job->queue_task(job,
				(task_t*)mode_config_create(this->ike_sa, TRUE, FALSE));
	}
	lib->processor->queue_job(lib->processor, (job_t*)job);
	return SUCCESS;
}

METHOD(task_t, build_i, status_t,
	private_xauth_t *this, message_t *message)
{
	if (!this->xauth)
	{
		cp_payload_t *cp = NULL;

		this->xauth = load_method(this);
		if (!this->xauth)
		{
			return FAILED;
		}
		switch (this->xauth->initiate(this->xauth, &cp))
		{
			case NEED_MORE:
				break;
			case SUCCESS:
				DESTROY_IF(cp);
				if (add_auth_cfg(this, NULL, FALSE) && allowed(this))
				{
					this->status = XAUTH_OK;
				}
				this->public.task.process = _process_i_status;
				return build_i_status(this, message);
			default:
				return FAILED;
		}
		message->add_payload(message, (payload_t *)cp);
		return NEED_MORE;
	}

	if (this->cp)
	{	/* send previously generated payload */
		message->add_payload(message, (payload_t *)this->cp);
		this->cp = NULL;
		return NEED_MORE;
	}
	return FAILED;
}

METHOD(task_t, build_r_ack, status_t,
	private_xauth_t *this, message_t *message)
{
	cp_payload_t *cp;

	cp = cp_payload_create_type(PLV1_CONFIGURATION, CFG_ACK);
	cp->set_identifier(cp, this->identifier);
	cp->add_attribute(cp,
			configuration_attribute_create_chunk(
					PLV1_CONFIGURATION_ATTRIBUTE, XAUTH_STATUS, chunk_empty));

	message->add_payload(message, (payload_t *)cp);

	if (this->status == XAUTH_OK && allowed(this) && establish(this))
	{
		return SUCCESS;
	}
	return FAILED;
}

METHOD(task_t, process_r, status_t,
	private_xauth_t *this, message_t *message)
{
	cp_payload_t *cp;

	if (!this->xauth)
	{
		this->xauth = load_method(this);
		if (!this->xauth)
		{	/* send empty reply */
			return NEED_MORE;
		}
	}
	cp = (cp_payload_t*)message->get_payload(message, PLV1_CONFIGURATION);
	if (!cp)
	{
		DBG1(DBG_IKE, "configuration payload missing in XAuth request");
		return FAILED;
	}
	if (cp->get_type(cp) == CFG_REQUEST)
	{
		/* Scan attributes to classify this request:
		 * - Standard XAUTH (types 16520+)
		 * - Check Point proprietary XAUTH (types 13-22 with different semantics)
		 * - Mode Config probe (SUBNET, SUPPORTED_ATTRIBUTES) */
		bool has_xauth_attrs = FALSE;
		bool has_modeconfig_attrs = FALSE;
		bool has_subnet = FALSE;
		bool has_sup = FALSE;
		bool has_cp_challenge = FALSE;
		configuration_attribute_type_t cp_response_type = 0;
		enumerator_t *enumerator;
		configuration_attribute_t *attribute;

		enumerator = cp->create_attribute_enumerator(cp);
		while (enumerator->enumerate(enumerator, &attribute))
		{
			configuration_attribute_type_t type = attribute->get_type(attribute);
			chunk_t data = attribute->get_chunk(attribute);
			if (type >= 16520 && type <= 16529)
			{
				has_xauth_attrs = TRUE;
			}
			else
			{
				has_modeconfig_attrs = TRUE;
				if (type == INTERNAL_IP4_SUBNET)
				{
					has_subnet = TRUE;
				}
				else if (type == SUPPORTED_ATTRIBUTES)
				{
					has_sup = TRUE;
				}
			}
			/* Check Point Challenge: type 18 (INTERNAL_IP6_PREFIX in IKE)
			 * carries "prompt\0(S-expression msg_obj)" */
			if (type == INTERNAL_IP6_PREFIX && data.len > 0 &&
				data.ptr != NULL && memchr(data.ptr, '\0', data.len))
			{
				has_cp_challenge = TRUE;
			}
			/* Find CP response type: first attribute that isn't
			 * AuthType(13=INTERNAL_IP4_SUBNET), Challenge(18=INTERNAL_IP6_PREFIX),
			 * or Status(20=P_CSCF_IP4_ADDRESS) but is a CP credential type:
			 * UserName(14=SUPPORTED_ATTRIBUTES), UserPassword(15=INTERNAL_IP6_SUBNET),
			 * Passcode(16=MIP6_HOME_PREFIX) */
			if (cp_response_type == 0 &&
				(type == SUPPORTED_ATTRIBUTES ||     /* 14 = CP UserName */
				 type == INTERNAL_IP6_SUBNET ||      /* 15 = CP UserPassword */
				 type == MIP6_HOME_PREFIX))           /* 16 = CP Passcode */
			{
				cp_response_type = type;
			}
		}
		enumerator->destroy(enumerator);

		if (cp_response_type != 0 && has_subnet)
		{
			/* === Check Point Proprietary XAUTH Exchange ===
			 * Gateway sent TRANSACTION CFG_REQUEST with CP-proprietary types:
			 *   AuthType(13) + UserName(14)/UserPassword(15)/Passcode(16)
			 *   Optionally: Challenge(18)="prompt\0(S-expression)"
			 * Response: CFG_REPLY with AuthType(13)=0 + credential in the
			 * response type (UserPassword/Passcode/UserName) */
			cp_payload_t *reply;
			uint16_t id;

			/* Log the challenge prompt */
			enumerator = cp->create_attribute_enumerator(cp);
			while (enumerator->enumerate(enumerator, &attribute))
			{
				if (attribute->get_type(attribute) == INTERNAL_IP6_PREFIX)
				{
					chunk_t data = attribute->get_chunk(attribute);
					uint8_t *nul = memchr(data.ptr, '\0', data.len);
					if (nul)
					{
						DBG1(DBG_IKE, "CP challenge: '%.*s'",
							 (int)(nul - data.ptr), data.ptr);
					}
				}
			}
			enumerator->destroy(enumerator);

			id = cp->get_identifier(cp);
			reply = cp_payload_create_type(PLV1_CONFIGURATION, CFG_REPLY);
			reply->set_identifier(reply, id);

			/* AuthType = Generic (short/TV attribute, CP type 13, value 0) */
			reply->add_attribute(reply,
				configuration_attribute_create_value(
					INTERNAL_IP4_SUBNET, 0));

			if (cp_response_type == SUPPORTED_ATTRIBUTES)
			{
				/* CP UserName (type 14): auto-respond with XAUTH username */
				identification_t *user_id = this->user;
				if (!user_id)
				{
					user_id = this->ike_sa->get_my_id(this->ike_sa);
				}
				if (user_id)
				{
					chunk_t name = user_id->get_encoding(user_id);
					DBG1(DBG_IKE, "CP XAUTH: sending username in attr %d",
						 cp_response_type);
					reply->add_attribute(reply,
						configuration_attribute_create_chunk(
							PLV1_CONFIGURATION_ATTRIBUTE,
							cp_response_type, name));
				}
			}
			else
			{
				/* CP UserPassword(15) or Passcode(16): send credential */
				shared_key_t *shared;
				identification_t *me, *other;

				me = this->ike_sa->get_my_id(this->ike_sa);
				other = this->ike_sa->get_other_id(this->ike_sa);
				shared = lib->credmgr->get_shared(lib->credmgr,
							SHARED_EAP, me, other);
				if (shared)
				{
					chunk_t secret = shared->get_key(shared);
					DBG1(DBG_IKE, "CP XAUTH: sending credential in attr %d",
						 cp_response_type);
					reply->add_attribute(reply,
						configuration_attribute_create_chunk(
							PLV1_CONFIGURATION_ATTRIBUTE,
							cp_response_type, secret));
					shared->destroy(shared);
				}
				else
				{
					DBG1(DBG_IKE, "CP XAUTH: no credential available");
				}
			}

			this->cp = reply;
			return NEED_MORE;
		}

		if (!has_xauth_attrs && has_modeconfig_attrs)
		{
			cp_payload_t *reply;
			uint16_t id;

			DBG1(DBG_IKE, "responding to pre-XAUTH Mode Config request "
				 "(SUBNET=%d SUP=%d)", has_subnet, has_sup);
			id = cp->get_identifier(cp);
			reply = cp_payload_create_type(PLV1_CONFIGURATION, CFG_REPLY);
			reply->set_identifier(reply, id);

			/* Re-iterate attributes and respond to each one */
			enumerator = cp->create_attribute_enumerator(cp);
			while (enumerator->enumerate(enumerator, &attribute))
			{
				configuration_attribute_type_t type = attribute->get_type(attribute);
				if (type == INTERNAL_IP4_SUBNET)
				{
					uint8_t subnet[8] = {0}; /* 0.0.0.0/0.0.0.0 = any */
					reply->add_attribute(reply,
						configuration_attribute_create_chunk(
							PLV1_CONFIGURATION_ATTRIBUTE,
							INTERNAL_IP4_SUBNET,
							chunk_create(subnet, sizeof(subnet))));
				}
				else if (type == INTERNAL_IP6_SUBNET)
				{
					uint8_t subnet6[18] = {0}; /* ::/0 */
					reply->add_attribute(reply,
						configuration_attribute_create_chunk(
							PLV1_CONFIGURATION_ATTRIBUTE,
							INTERNAL_IP6_SUBNET,
							chunk_create(subnet6, sizeof(subnet6))));
				}
				else if (type == INTERNAL_IP6_PREFIX)
				{
					/* Check Point encodes password/challenge prompts in this
					 * attribute as: "prompt text\0(msg_obj S-expression...)" */
					chunk_t data = attribute->get_chunk(attribute);
					if (data.len > 0 && data.ptr != NULL &&
						memchr(data.ptr, '\0', data.len) != NULL)
					{
						/* This contains a challenge prompt — respond with
						 * the password from the credential manager */
						char *prompt = (char *)data.ptr;
						shared_key_t *shared;
						identification_t *me, *other;

						DBG1(DBG_IKE, "Check Point challenge: '%s'", prompt);
						/* Log the S-expression after null for debugging */
						{
							uint8_t *null_pos = memchr(data.ptr, '\0', data.len);
							if (null_pos)
							{
								size_t sexpr_off = (null_pos - data.ptr) + 1;
								size_t sexpr_len = data.len - sexpr_off;
								if (sexpr_len > 0 && sexpr_len < 2048)
								{
									DBG1(DBG_IKE, "  challenge sexpr: '%.*s'",
										 (int)sexpr_len, data.ptr + sexpr_off);
								}
							}
						}
						me = this->ike_sa->get_my_id(this->ike_sa);
						other = this->ike_sa->get_other_id(this->ike_sa);
						shared = lib->credmgr->get_shared(lib->credmgr,
									SHARED_EAP, me, other);
						if (shared)
						{
							chunk_t secret = shared->get_key(shared);
							reply->add_attribute(reply,
								configuration_attribute_create_chunk(
									PLV1_CONFIGURATION_ATTRIBUTE,
									INTERNAL_IP6_PREFIX,
									secret));
							shared->destroy(shared);
						}
						else
						{
							DBG1(DBG_IKE, "no credentials available for CP challenge");
							reply->add_attribute(reply,
								configuration_attribute_create_chunk(
									PLV1_CONFIGURATION_ATTRIBUTE,
									INTERNAL_IP6_PREFIX, chunk_empty));
						}
					}
					else
					{
						uint8_t pfx6[17] = {0};
						reply->add_attribute(reply,
							configuration_attribute_create_chunk(
								PLV1_CONFIGURATION_ATTRIBUTE,
								INTERNAL_IP6_PREFIX,
								chunk_create(pfx6, sizeof(pfx6))));
					}
				}
				else if (type == SUPPORTED_ATTRIBUTES)
				{
					uint16_t attrs[] = {
						htons(INTERNAL_IP4_ADDRESS),
						htons(INTERNAL_IP4_NETMASK),
						htons(INTERNAL_IP4_DNS),
						htons(INTERNAL_IP4_SUBNET),
						htons(XAUTH_TYPE),
						htons(XAUTH_USER_NAME),
						htons(XAUTH_USER_PASSWORD),
						htons(XAUTH_PASSCODE),
						htons(XAUTH_MESSAGE),
						htons(XAUTH_CHALLENGE),
						htons(XAUTH_STATUS),
					};
					reply->add_attribute(reply,
						configuration_attribute_create_chunk(
							PLV1_CONFIGURATION_ATTRIBUTE,
							SUPPORTED_ATTRIBUTES,
							chunk_create((uint8_t*)attrs, sizeof(attrs))));
				}
				else
				{
					/* Echo back unknown non-XAUTH attributes with empty data */
					reply->add_attribute(reply,
						configuration_attribute_create_chunk(
							PLV1_CONFIGURATION_ATTRIBUTE,
							type, chunk_empty));
				}
			}
			enumerator->destroy(enumerator);

			this->cp = reply;
			return NEED_MORE;
		}

		switch (this->xauth->process(this->xauth, cp, &this->cp))
		{
			case NEED_MORE:
				return NEED_MORE;
			case SUCCESS:
			case FAILED:
			default:
				break;
		}
		this->cp = NULL;
		return NEED_MORE;
	}
	if (cp->get_type(cp) == CFG_SET)
	{
		/* Check Point gateways use CFG_SET for:
		 * 1) Mode Config push (non-XAUTH attrs) before XAUTH
		 * 2) XAUTH status response with CP Status(20) after auth
		 * 3) Standard XAUTH with types 16520+ */
		bool has_xauth_set = FALSE;
		bool has_cp_status = FALSE;
		uint16_t cp_status_val = 0;
		configuration_attribute_t *attr_check;
		enumerator_t *set_enum;

		set_enum = cp->create_attribute_enumerator(cp);
		while (set_enum->enumerate(set_enum, &attr_check))
		{
			configuration_attribute_type_t stype = attr_check->get_type(attr_check);
			if (stype >= 16520 && stype <= 16529)
			{
				has_xauth_set = TRUE;
			}
			/* CP Status: type 20 (P_CSCF_IP4_ADDRESS in IKE) */
			if (stype == P_CSCF_IP4_ADDRESS)
			{
				has_cp_status = TRUE;
				cp_status_val = attr_check->get_value(attr_check);
				DBG1(DBG_IKE, "CP Status attribute: value=%d", cp_status_val);
			}
			/* Log CP Message (type 17 = INTERNAL_IP6_LINK) for debugging */
			if (stype == INTERNAL_IP6_LINK)
			{
				chunk_t mdata = attr_check->get_chunk(attr_check);
				if (mdata.len > 0 && mdata.len < 2048)
				{
					uint8_t *nul = memchr(mdata.ptr, '\0', mdata.len);
					if (nul)
					{
						DBG1(DBG_IKE, "CP Message: '%.*s'",
							 (int)(nul - mdata.ptr), mdata.ptr);
					}
				}
			}
		}
		set_enum->destroy(set_enum);

		if (has_cp_status)
		{
			/* Check Point XAUTH status response */
			cp_payload_t *ack;
			ack = cp_payload_create_type(PLV1_CONFIGURATION, CFG_ACK);
			ack->set_identifier(ack, cp->get_identifier(cp));
			/* Echo the Status attribute in the ACK */
			ack->add_attribute(ack,
				configuration_attribute_create_value(
					P_CSCF_IP4_ADDRESS, cp_status_val));
			this->cp = ack;

			if (cp_status_val == 1)
			{
				DBG1(DBG_IKE, "CP XAUTH authentication succeeded");
				this->status = XAUTH_OK;
				identification_t *user_id = this->user;
				if (!user_id)
				{
					user_id = this->ike_sa->get_my_id(this->ike_sa);
				}
				add_auth_cfg(this, user_id, TRUE);
			}
			else
			{
				DBG1(DBG_IKE, "CP XAUTH authentication failed (status=%d)",
					 cp_status_val);
				this->status = XAUTH_FAILED;
			}
			this->identifier = cp->get_identifier(cp);
			this->public.task.build = _build_r_ack;
			return NEED_MORE;
		}

		if (!has_xauth_set)
		{
			cp_payload_t *ack;

			DBG1(DBG_IKE, "acknowledging pre-XAUTH Mode Config push");
			ack = cp_payload_create_type(PLV1_CONFIGURATION, CFG_ACK);
			ack->set_identifier(ack, cp->get_identifier(cp));

			/* Log and echo attribute types for debugging */
			set_enum = cp->create_attribute_enumerator(cp);
			while (set_enum->enumerate(set_enum, &attr_check))
			{
				chunk_t data = attr_check->get_chunk(attr_check);
				DBG1(DBG_IKE, "  CPS attr type %d, len %zu",
					 attr_check->get_type(attr_check), data.len);
				if (data.len > 0 && data.len < 2048)
				{
					/* Check if data contains a null byte (S-expr) */
					void *null_pos = memchr(data.ptr, '\0', data.len);
					if (null_pos)
					{
						/* Print the text part before null */
						size_t text_len = (uint8_t*)null_pos - data.ptr;
						if (text_len > 0 && text_len < 256)
						{
							DBG1(DBG_IKE, "  CPS text: '%.*s'",
								 (int)text_len, data.ptr);
						}
						/* Print the S-expr part after null */
						size_t sexpr_off = text_len + 1;
						size_t sexpr_len = data.len - sexpr_off;
						if (sexpr_len > 0 && sexpr_len < 2048)
						{
							DBG1(DBG_IKE, "  CPS sexpr(%zu): '%.*s'",
								 sexpr_len, (int)sexpr_len,
								 data.ptr + sexpr_off);
						}
					}
					else if (data.len < 512)
					{
						/* Try printing as plain text */
						bool printable = TRUE;
						size_t i;
						for (i = 0; i < data.len && i < 256; i++)
						{
							if (data.ptr[i] < 0x20 || data.ptr[i] > 0x7e)
							{
								printable = FALSE;
								break;
							}
						}
						if (printable)
						{
							DBG1(DBG_IKE, "  CPS text: '%.*s'",
								 (int)data.len, data.ptr);
						}
					}
				}
				ack->add_attribute(ack,
					configuration_attribute_create_chunk(
						PLV1_CONFIGURATION_ATTRIBUTE,
						attr_check->get_type(attr_check), chunk_empty));
			}
			set_enum->destroy(set_enum);

			this->cp = ack;
			/* Continue waiting for XAUTH challenge from gateway */
			return NEED_MORE;
		}

		configuration_attribute_t *attribute;
		enumerator_t *enumerator;

		enumerator = cp->create_attribute_enumerator(cp);
		while (enumerator->enumerate(enumerator, &attribute))
		{
			if (attribute->get_type(attribute) == XAUTH_STATUS)
			{
				this->status = attribute->get_value(attribute);
			}
		}
		enumerator->destroy(enumerator);
		if (this->status == XAUTH_OK &&
			add_auth_cfg(this, this->xauth->get_identity(this->xauth), TRUE))
		{
			DBG1(DBG_IKE, "XAuth authentication of '%Y' (myself) successful",
				 this->xauth->get_identity(this->xauth));
		}
		else
		{
			DBG1(DBG_IKE, "XAuth authentication of '%Y' (myself) failed",
				 this->xauth->get_identity(this->xauth));
		}
	}
	this->identifier = cp->get_identifier(cp);
	this->public.task.build = _build_r_ack;
	return NEED_MORE;
}

METHOD(task_t, build_r, status_t,
	private_xauth_t *this, message_t *message)
{
	if (!this->cp)
	{	/* send empty reply if building data failed */
		this->cp = cp_payload_create_type(PLV1_CONFIGURATION, CFG_REPLY);
	}
	message->add_payload(message, (payload_t *)this->cp);
	this->cp = NULL;
	return NEED_MORE;
}

METHOD(task_t, process_i, status_t,
	private_xauth_t *this, message_t *message)
{
	identification_t *id;
	cp_payload_t *cp;

	cp = (cp_payload_t*)message->get_payload(message, PLV1_CONFIGURATION);
	if (!cp)
	{
		DBG1(DBG_IKE, "configuration payload missing in XAuth response");
		return FAILED;
	}
	switch (this->xauth->process(this->xauth, cp, &this->cp))
	{
		case NEED_MORE:
			return NEED_MORE;
		case SUCCESS:
			id = this->xauth->get_identity(this->xauth);
			DBG1(DBG_IKE, "XAuth authentication of '%Y' successful", id);
			if (add_auth_cfg(this, id, FALSE) && allowed(this))
			{
				this->status = XAUTH_OK;
			}
			break;
		case FAILED:
			DBG1(DBG_IKE, "XAuth authentication of '%Y' failed",
				 this->xauth->get_identity(this->xauth));
			break;
		default:
			return FAILED;
	}
	this->public.task.build = _build_i_status;
	this->public.task.process = _process_i_status;
	return NEED_MORE;
}

METHOD(task_t, get_type, task_type_t,
	private_xauth_t *this)
{
	return TASK_XAUTH;
}

METHOD(task_t, migrate, void,
	private_xauth_t *this, ike_sa_t *ike_sa)
{
	DESTROY_IF(this->xauth);
	DESTROY_IF(this->cp);

	this->ike_sa = ike_sa;
	this->xauth = NULL;
	this->cp = NULL;
	this->user = NULL;
	this->status = XAUTH_FAILED;

	if (this->initiator)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}
}

METHOD(xauth_t, queue_mode_config_push, void,
	private_xauth_t *this)
{
	this->mode_config_push = TRUE;
}

METHOD(task_t, destroy, void,
	private_xauth_t *this)
{
	DESTROY_IF(this->xauth);
	DESTROY_IF(this->cp);
	free(this);
}

/*
 * Described in header.
 */
xauth_t *xauth_create(ike_sa_t *ike_sa, bool initiator)
{
	private_xauth_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
			.queue_mode_config_push = _queue_mode_config_push,
		},
		.initiator = initiator,
		.ike_sa = ike_sa,
		.status = XAUTH_FAILED,
	);

	if (initiator)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}
	return &this->public;
}
