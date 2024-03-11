import asyncio
import json
import time

from indy import pool, wallet, did, ledger, anoncreds, blob_storage
from indy.error import ErrorCode, IndyError
from indy.pairwise import get_pairwise

from os.path import dirname


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp=None):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Get Revocation Definitions and Revocation Registries
            print("\"{}\" -> Get Revocation Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_def_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            print("\"{}\" -> Get Revocation Registry from Ledger".format(actor))
            if not timestamp: timestamp = item['timestamp']
            get_revoc_reg_request = \
                await ledger.build_get_revoc_reg_request(_did, item['rev_reg_id'], timestamp)
            get_revoc_reg_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, rev_reg_json, timestamp2) = await ledger.parse_get_revoc_reg_response(get_revoc_reg_response)

            rev_regs[rev_reg_id] = {timestamp2: json.loads(rev_reg_json)}
            rev_reg_defs[rev_reg_id] = json.loads(revoc_reg_def_json)

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ensure_previous_request_applied(
        pool_handle, get_schema_request, lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = \
        await ensure_previous_request_applied(pool_handle, get_cred_def_request,
                                              lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)



async def ensure_previous_request_applied(pool_handle, checker_request, checker):
    for _ in range(3):
        response = json.loads(await ledger.submit_request(pool_handle, checker_request))
        try:
            if checker(response):
                return json.dumps(response)
        except TypeError:
            pass
        time.sleep(5)


async def create_wallet(identity):
    print("\"{}\" -> Create wallet".format(identity['name']))
    try:
        await wallet.create_wallet(identity['wallet_config'],
                                   identity['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    identity['wallet'] = await wallet.open_wallet(identity['wallet_config'],
                                                  identity['wallet_credentials'])



async def getting_verinym(from_, to):
    await create_wallet(to)

    (to['did'], to['key']) = await did.create_and_store_my_did(to['wallet'], "{}")

    from_['info'] = {
        'did': to['did'],
        'verkey': to['key'],
        'role': to['role'] or None
    }

    await send_nym(from_['pool'], from_['wallet'], from_['did'], from_['info']['did'],
                   from_['info']['verkey'], from_['info']['role'])


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    print(nym_request)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp_from=None,
                                          timestamp_to=None):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.", item['schema_id'])
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Create Revocations States
            print("\"{}\" -> Get Revocation Registry Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_def_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            print("\"{}\" -> Get Revocation Registry Delta from Ledger".format(actor))
            if not timestamp_to: timestamp_to = int(time.time())
            get_revoc_reg_delta_request = \
                await ledger.build_get_revoc_reg_delta_request(_did, item['rev_reg_id'], timestamp_from, timestamp_to)
            get_revoc_reg_delta_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_delta_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_delta_json, t) = \
                await ledger.parse_get_revoc_reg_delta_response(get_revoc_reg_delta_response)

            tails_reader_config = json.dumps(
                {'base_dir': dirname(json.loads(revoc_reg_def_json)['value']['tailsLocation']),
                 'uri_pattern': ''})
            blob_storage_reader_cfg_handle = await blob_storage.open_reader('default', tails_reader_config)

            print('%s - Create Revocation State', actor)
            rev_state_json = \
                await anoncreds.create_revocation_state(blob_storage_reader_cfg_handle, revoc_reg_def_json,
                                                        revoc_reg_delta_json, t, item['cred_rev_id'])
            rev_states[rev_reg_id] = {t: json.loads(rev_state_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def run():

    pool_ = {
        'name': 'pool1'
    }
    print("Open Pool Ledger: {}".format(pool_['name']))
    pool_['genesis_txn_path'] = "pool1.txn"
    pool_['config'] = json.dumps({"genesis_txn": str(pool_['genesis_txn_path'])})

    print(pool_)

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(2)

    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print(pool_['handle'])
    #    --------------------------------------------------------------------------
    #  Accessing a steward.

    steward = {
        'name': "Sovrin Steward",
        'wallet_config': json.dumps({'id': 'sovrin_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }
    print(steward)

    await create_wallet(steward)

    print(steward["wallet"])

    steward["did_info"] = json.dumps({'seed':steward['seed']})
    print(steward["did_info"])

    # did:demoindynetwork:Th7MpTaRZVRYnPiabds81Y
    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'], steward['did_info'])
  
    #================== Step-1 Identity Setup(did) ========================
    # ----------------------------------------------------------------------
    # Create and register dids for Passport , VISA Center and Immigration 

    #print("\n\n\n==============================")
    #print("==  Government registering Verinym  ==")
    #print("------------------------------")


    government = {
        'name': 'Government',
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, government)



    print("=========================================")
    print("== Passport office getting Verinym  ==")
    print("--------------------------------------")

    thepassportoffice = {
        'name': 'thepassportoffice',
        'wallet_config': json.dumps({'id': 'thepassportoffice_wallet'}),
        'wallet_credentials': json.dumps({'key': 'thepassportoffice_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, thepassportoffice)

    print("\n=============================================")
    print("===== VISA Center getting Verinym  =========")
    print("-------------------------------------------\n")

    visacenter = {
        'name': 'visacenter',
        'wallet_config': json.dumps({'id': 'visacenter_wallet'}),
        'wallet_credentials': json.dumps({'key': 'visacenter_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, visacenter)


    #Immigration Identity(Verinym) Setup
    print("\n=============================================")
    print("===== Immigration getting Verinym  =========")
    print("-------------------------------------------\n")

    theimmigration = {
        'name': 'theimmigration',
        'wallet_config': json.dumps({'id': 'theimmigration_wallet'}),
        'wallet_credentials': json.dumps({'key': 'theimmigration_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, theimmigration)

    #--------------------Police------------------
    #Police Station identity(Verinym) Setup
    print("\n=============================================")
    print("===== Police Station getting Verinym  =========")
    print("-------------------------------------------\n")

    policestation = {
        'name': 'policestation',
        'wallet_config': json.dumps({'id': 'policestation_wallet'}),
        'wallet_credentials': json.dumps({'key': 'policestation_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, policestation)


    #=============Step-2 Schema Setup==============
    # =============================================
    # =============Passport Schema Setup ==========

    print("Creating \"Passport\" Schema \n")
    passport= {
        'name': 'passport',
        'version': '1.0',
        'attributes': ['first_name', 'last_name', 'dob', 'issuedate', 'expiry', 'passport_no','adult']
    }
    (government['passport_schema_id'], government['passport_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], passport['name'], passport['version'],
                                             json.dumps(passport['attributes']))
    print(" Passport Schema Structure  \n")
    print(government['passport_schema'])
    passport_schema_id = government['passport_schema_id']

    print(government['passport_schema_id'], government['passport_schema'])

    #print("\"Government\" -> Send \"passport\" Schema to Ledger")

    
    schema_request = await ledger.build_schema_request(government['did'], government['passport_schema'])
    await ledger.sign_and_submit_request(government['pool'], government['wallet'], government['did'], schema_request)
    
    #==========Passport Schema setup Completed============

    # =============================================
    # =============VISA Schema Setup ==========

    print("\nCreating \"VISA\" Schema \n")
    visa= {
        'name': 'visa',
        'version': '2.0',
        'attributes': ['first_name', 'last_name','visa_no','expiry','p_no' ,'type']
    }
    (government['visa_schema_id'], government['visa_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], visa['name'], visa['version'],
                                             json.dumps(visa['attributes']))
    
    print("VISA Schema Structure \n")
    print(government['visa_schema'])
    visa_schema_id = government['visa_schema_id']

    print(government['visa_schema_id'], government['visa_schema'])

    #print("\"Government\" -> Send \"VISA\" Schema to Ledger")

    
    schema_request = await ledger.build_schema_request(government['did'], government['visa_schema'])
    await ledger.sign_and_submit_request(government['pool'], government['wallet'], government['did'], schema_request)
    
    #==========VISA Schema setup Completed============


    # ==================================================
    # =============Immigration Schema Setup =============

    print("\nCreating \"Immigration\" Schema \n")
    immigration= {
        'name': 'immigration',
        'version': '3.0',
        'attributes': ['first_name', 'last_name','passport_no','visa_no','type', 'date']
    }
    (government['immigration_schema_id'], government['immigration_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], immigration['name'], immigration['version'],
                                             json.dumps(immigration['attributes']))
    
    print("Immigration Schema Structure \n")
    print(government['immigration_schema'])
    immigration_schema_id = government['immigration_schema_id']

    print(government['immigration_schema_id'], government['immigration_schema'])

    #print("\"Government\" -> Send \"immigration\" Schema to Ledger")

    
    schema_request = await ledger.build_schema_request(government['did'], government['immigration_schema'])
    await ledger.sign_and_submit_request(government['pool'], government['wallet'], government['did'], schema_request)
    
    #==========Immigration Schema setup Completed============

  
    # =======================================================
    # =============Police clearance  Schema Setup =============

    print("Creating \"Police Clearance \" Schema \n")
    pclearance= {
        'name': 'pclearance',
        'version': '4.0',
        'attributes': ['name','issue-date','pass_no','status']
    }
    (government['pclearance_schema_id'], government['pclearance_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], pclearance['name'], pclearance['version'],
                                             json.dumps(pclearance['attributes']))
    print("Police Clearance Schema Structure  \n")
    print(government['pclearance_schema'])
    pclearance_schema_id = government['pclearance_schema_id']

    print(government['pclearance_schema_id'], government['pclearance_schema'])

    #print("\"Government\" -> Send \"Police Clearance \" Schema to Ledger")

    schema_request = await ledger.build_schema_request(government['did'], government['pclearance_schema'])
    await ledger.sign_and_submit_request(government['pool'], government['wallet'], government['did'], schema_request)
    #==========Police Clearance Schema setup Completed============


    #=============Step-3 Credential Definition Setup=============
    # -----------------------------------------------------
    #  **********Passport credential definition************
    
    print("\n\n================================================")
    print("=== PassportCredential Definition Setup by Passport Office ==\n")
    print("----------------------------------------------------\n")

    print("\"The Passport office\" -> Get \"Passport\" Schema from Ledger\n")

    # GET SCHEMA FROM LEDGER
    get_schema_request = await ledger.build_get_schema_request(thepassportoffice['did'], passport_schema_id)
    get_schema_response = await ensure_previous_request_applied(
        thepassportoffice['pool'], get_schema_request, lambda response: response['result']['data'] is not None)
    (thepassportoffice['passport_schema_id'], thepassportoffice['passport_schema']) = await ledger.parse_get_schema_response(get_schema_response)

    # Passport CREDENTIAL DEFINITION
    print("\"The Passport Office\" -> Create and store in Wallet \"Passport\" Credential Definition")
    passport_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (thepassportoffice['passport_cred_def_id'], thepassportoffice['passport_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(thepassportoffice['wallet'], thepassportoffice['did'],
                                                               thepassportoffice['passport_schema'], passport_cred_def['tag'],
                                                               passport_cred_def['type'],
                                                               json.dumps(passport_cred_def['config']))

    print("\"The Passport office\" -> Send  Passport Credential Definition to Ledger\n")

    # print(thepassportoffice['passport_cred_def'])

    cred_def_request = await ledger.build_cred_def_request(thepassportoffice['did'], thepassportoffice['passport_cred_def'])
    # print(cred_def_request)
    await ledger.sign_and_submit_request(thepassportoffice['pool'], thepassportoffice['wallet'], thepassportoffice['did'], cred_def_request)
    print("\n\n>>>>>>>>>>>>>>>>>>>>>>.\n\n", thepassportoffice['passport_cred_def_id'])

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #===============>VISA Credential Definition Setup<==========
    # -----------------------------------------------------
    # ************ VISA credential definition *****************
    
    print("\n\n==================================================")
    print("======= VISA Credential Definition Setup by VISA Center ======= \n")
    print("----------------------------------------------------\n")

    print("\"VISA Center\" -> Get \"VISA\" Schema from Ledger \n ")

    # GET SCHEMA FROM LEDGER
    get_schema_request = await ledger.build_get_schema_request(visacenter['did'], visa_schema_id)
    get_schema_response = await ensure_previous_request_applied(
        visacenter['pool'], get_schema_request, lambda response: response['result']['data'] is not None)
    (visacenter['visa_schema_id'], visacenter['visa_schema']) = await ledger.parse_get_schema_response(get_schema_response)

    # VISA CREDENTIAL DEFINITION
    print("\"Visa Center \" -> Create and store in Wallet \"VISA \" Credential Definition \n ")
    visa_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (visacenter['visa_cred_def_id'], visacenter['visa_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(visacenter['wallet'], visacenter['did'],
                                                               visacenter['visa_schema'], visa_cred_def['tag'],
                                                               visa_cred_def['type'],
                                                               json.dumps(visa_cred_def['config']))

    print("\"VISA Center \" -> Send  \"VISA \" Credential Definition to Ledger \n ")
    # print(visacenter['visa_cred_def'])

    cred_def_request = await ledger.build_cred_def_request(visacenter['did'], visacenter['visa_cred_def'])
    # print(cred_def_request)
    await ledger.sign_and_submit_request(visacenter['pool'], visacenter['wallet'], visacenter['did'], cred_def_request)
    print("\n\n=====>>>>>>>>>>>>>>>><<<<<<<<=======\n\n", visacenter['visa_cred_def_id'])


    #-------==================><============================----------
    # -----------------------------------------------------
    #  **********Immigration credential definition************
    
    print("\n\n================================================")
    print("=== Immigration Credential Definition Setup by the Immigration ==\n")
    print("----------------------------------------------------\n")

    print("\"The Immigration office\" -> Get \"immigration\" Schema from Ledger\n")

    # GET SCHEMA FROM LEDGER
    get_schema_request = await ledger.build_get_schema_request(theimmigration['did'], immigration_schema_id)
    get_schema_response = await ensure_previous_request_applied(
        theimmigration['pool'], get_schema_request, lambda response: response['result']['data'] is not None)
    (theimmigration['immigration_schema_id'], theimmigration['immigration_schema']) = await ledger.parse_get_schema_response(get_schema_response)

    # Immigration CREDENTIAL DEFINITION
    print("The Immigration Office -> Create and store in Wallet \"Immigration\" Credential Definition")
    immigration_cred_def = {
        'tag': 'TAG3',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (theimmigration['immigration_cred_def_id'], theimmigration['immigration_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(theimmigration['wallet'], theimmigration['did'],
                                                               theimmigration['immigration_schema'], immigration_cred_def['tag'],
                                                               immigration_cred_def['type'],
                                                               json.dumps(immigration_cred_def['config']))

    print("\"The Immigration office\" -> Send  Immigration Credential Definition to Ledger\n")

    # print(theimmigration['immigration_cred_def'])

    cred_def_request = await ledger.build_cred_def_request(theimmigration['did'], theimmigration['immigration_cred_def'])

    # print(cred_def_request)
    await ledger.sign_and_submit_request(theimmigration['pool'], theimmigration['wallet'], theimmigration['did'], cred_def_request)
    print("\n\n>>>>>>>>>>>>>>>>>>>>>>.\n\n", theimmigration['immigration_cred_def_id'])

    #===========================Police Clearance Credential Definition Setup=============
    # -----------------------------------------------------
    #  **********Police Clearance credential definition************
    
    print("\n\n================================================")
    print("=== Police Clearance  Definition Setup by Police Station ==\n")
    print("----------------------------------------------------\n")

    print("\"Police Station \" -> Get \"Police Clearance\" Schema from Ledger\n")

    # GET SCHEMA FROM LEDGER
    get_schema_request = await ledger.build_get_schema_request(policestation['did'], pclearance_schema_id)
    get_schema_response = await ensure_previous_request_applied(
        policestation['pool'], get_schema_request, lambda response: response['result']['data'] is not None)
    (policestation['pclearance_schema_id'], policestation['pclearance_schema']) = await ledger.parse_get_schema_response(get_schema_response)

    # Clearance CREDENTIAL DEFINITION
    print("\"Police Station \" -> Create and store in Wallet Credential Definition")
    pclearance_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (policestation['pclearance_cred_def_id'], policestation['pclearance_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(policestation['wallet'], policestation['did'],
                                                               policestation['pclearance_schema'], pclearance_cred_def['tag'],
                                                               pclearance_cred_def['type'],
                                                               json.dumps(pclearance_cred_def['config']))

    print("\"Police Station \" -> Send  Police Clearance Credential Definition to Ledger\n")

    #print(policestation['pclearance_cred_def'])

    cred_def_request = await ledger.build_cred_def_request(policestation['did'], policestation['pclearance_cred_def'])

    # print(cred_def_request)
    await ledger.sign_and_submit_request(policestation['pool'], policestation['wallet'], policestation['did'], cred_def_request)
    print("\n\n>>>>>>>>>>>>>>>>>>>>>>.\n\n", policestation['pclearance_cred_def_id'])


    #======================Step-4 ======================
    # -------==============><=====================----------
    #  Applicant Wallet and Identity Setup 

   
    print("\n == Saifur Setup (Wallet and Identity) == \n ")
    print("-----------------------------------------------\n")

    saifur = {
        'name': 'saifur',
        'wallet_config': json.dumps({'id': 'saifur_wallet'}),
        'wallet_credentials': json.dumps({'key': 'saifur_wallet_key'}),
        'pool': pool_['handle'],
    }
    await create_wallet(saifur)
    (saifur['did'], saifur['key']) = await did.create_and_store_my_did(saifur['wallet'], "{}")


    print("=======================================================\n")
    print("====== Getting passport from the Passport office ======\n")
    print("========================================================\n")

    #====================== Step-5 making passport =================================
    #---------------------------------------------------------------------------------
    #===================Credential Send and Receive Section ==========================
    #===========>*Passport-Office creates passport credential offer*<=================

    print("\"The Passport office\" -> Create \"passport\" Credential Offer for Saifur\n")
    thepassportoffice['passport_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(thepassportoffice['wallet'], thepassportoffice['passport_cred_def_id'])

    print("\"The Passport office\" -> Send \"passport\" Credential Offer to Saifur\n")
    
    # Over Network 
    saifur['passport_cred_offer'] = thepassportoffice['passport_cred_offer']

    print("Passport Credential Offer (maybe Structure) \n")
    print(saifur['passport_cred_offer'])

    # saifur prepares a passportc redential request

    passport_cred_offer_object = json.loads(saifur['passport_cred_offer'])

    saifur['passport_schema_id'] = passport_cred_offer_object['schema_id']
    saifur['passport_cred_def_id'] = passport_cred_offer_object['cred_def_id']

    print("\"Saifur\" -> Create and store \"saifur\" Master Secret in Wallet\n")
    saifur['master_secret_id'] = await anoncreds.prover_create_master_secret(saifur['wallet'], None)

    print("\n\"Saifur\" -> Get \"the passport office passport\" Credential Definition from Ledger \n ")
    (saifur['thepassportoffice_passport_cred_def_id'], saifur['thepassportoffice_passport_cred_def']) = \
        await get_cred_def(saifur['pool'], saifur['did'], saifur['passport_cred_def_id'])

    print("\"Saifur\" -> Create \"passport\" Credential Request for The Passport office\n")
    (saifur['passport_cred_request'], saifur['passport_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(saifur['wallet'], saifur['did'],
                                                     saifur['passport_cred_offer'],
                                                     saifur['thepassportoffice_passport_cred_def'],
                                                     saifur['master_secret_id'])

    print("\"Saifur\" -> Send \"passport\" Credential Request to the passport office \n")

    # Over Network
    thepassportoffice['passport_cred_request'] = saifur['passport_cred_request']


    #Passport issues credential to saifur ----------------
    print("\"The passport office\" -> Create \"Passport\" Credential for Saifur\n")
    thepassportoffice['saifur_passport_cred_values'] = json.dumps({
        "first_name": {"raw": "saifur", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "shamim", "encoded": "5321642780241790123587902456789123452"},
        "dob": {"raw": "10 January 1998", "encoded": "12434523576212321"},
        "issuedate": {"raw": "17 April 2021 ", "encoded": "2213454313412354"},
        "expiry": {"raw": "18 April 2026", "encoded": "2213454313412357"},
        "passport_no": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "adult": {"raw": "1", "encoded": "5"}
    })
    thepassportoffice['passport_cred'], _, _ = \
        await anoncreds.issuer_create_credential(thepassportoffice['wallet'], thepassportoffice['passport_cred_offer'],
                                                 thepassportoffice['passport_cred_request'],
                                                 thepassportoffice['saifur_passport_cred_values'], None, None)

    print("\"The Passport office\" -> Send \"Passport\" Credential to Saifur\n After Assigning Value \n")
    print(thepassportoffice['passport_cred'])
    # Over the network
    saifur['passport_cred'] = thepassportoffice['passport_cred']

    print("\"Saifur\" -> Store \"passport\" Credential from the passport office")
    _, saifur['passport_cred_def'] = await get_cred_def(saifur['pool'], saifur['did'],
                                                         saifur['passport_cred_def_id'])

    await anoncreds.prover_store_credential(saifur['wallet'], None, saifur['passport_cred_request_metadata'],
                                            saifur['passport_cred'], saifur['passport_cred_def'], None)
    
    print("\n\n>>>>>>>>>Stored After Wallet >>>>>>>>>>>>.\n\n", saifur['passport_cred_def'])


    #====================> [Step 5.2] <=====================================
    # Verifiable Presentation
    # Creating application request (presentaion request) --- validator - Police Station 

    print("\n\"Police Station \" -> Create  Proof Request \n")
    nonce = await anoncreds.generate_nonce()
    policestation['pclearance_application_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'pclearance-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr2_referent': {
                'name': 'last_name',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr3_referent': {
                'name': 'dob',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'passport_no',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'address'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'adult',
                'p_type': '>=',
                'p_value': 1,
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            }
        }
    })

    print("\"Police Station \" -> Send Proof Request to Saifur\n")

    # Over Network
    saifur['pclearance_application_proof_request'] = policestation['pclearance_application_proof_request']

    print("proof request\n")
    print(saifur['pclearance_application_proof_request'])

    # saifur prepares the presentation ===================================

    print("\n\n>>>>>>>>>>Same or Not >>>>>>>>>>>>.\n\n", saifur['pclearance_application_proof_request'])

    print("\"Saifur\" -> Get credentials for Proof Request")

    search_for_pclearance_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(saifur['wallet'],
                                                                saifur['pclearance_application_proof_request'], None)
    
    print("----------Searching(what is the next Value See-->line==637)---------------\n")
    print(search_for_pclearance_application_proof_request)
    print("----------------------------------\n")

    cred_for_attr1 = await get_credential_for_referent(search_for_pclearance_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_pclearance_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_pclearance_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_pclearance_application_proof_request, 'attr4_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_pclearance_application_proof_request, 'predicate1_referent')
    
    print("-----------cred_for_attr1 = ----------------")
    print(cred_for_attr1)
    print("---------------------------\n")


    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_pclearance_application_proof_request)

    saifur['creds_for_pclearance_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_predicate1['referent']: cred_for_predicate1}

    print("+++++++++++++++++++++After Searching(saifur['creds_for_pclearance_application_proof']) +++++++++++++++++++++++++++++++++++++\n")
    print(saifur['creds_for_pclearance_application_proof'])

    saifur['schemas_for_pclearance_application'], saifur['cred_defs_for_pclearance_application'], \
    saifur['revoc_states_for_pclearance_application'] = \
        await prover_get_entities_from_ledger(saifur['pool'], saifur['did'],
                                              saifur['creds_for_pclearance_application_proof'], saifur['name'])

    print("\"--Saifur--\" -> Create Proof\n")
    saifur['pclearance_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr5_referent': 'Sylhet'
        },
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
            'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    saifur['pclearance_application_proof'] = \
        await anoncreds.prover_create_proof(saifur['wallet'], saifur['pclearance_application_proof_request'],
                                            saifur['pclearance_application_requested_creds'], saifur['master_secret_id'],
                                            saifur['schemas_for_pclearance_application'],
                                            saifur['cred_defs_for_pclearance_application'],
                                            saifur['revoc_states_for_pclearance_application'])
    

    print("\n========== After Proving ======= \n")
    print(saifur['pclearance_application_proof'])

    print("\n\"Saifur\" -> Send  Proof to Police Station \n")

    # Over Network
    policestation['pclearance_application_proof'] = saifur['pclearance_application_proof']
    

    # Validating the verifiable presentation
    pclearance_application_proof_object = json.loads(policestation['pclearance_application_proof'])

    policestation['schemas_for_pclearance_application'], policestation['cred_defs_for_pclearance_application'], \
    policestation['revoc_ref_defs_for_pclearance_application'], policestation['revoc_regs_for_pclearance_application'] = \
        await verifier_get_entities_from_ledger(policestation['pool'], policestation['did'],
                                                pclearance_application_proof_object['identifiers'], policestation['name'])

    print("\"Police Station \" -> Verify  Proof from Saifur\n")

    assert 'saifur' == \
           pclearance_application_proof_object['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert 'shamim' == \
           pclearance_application_proof_object['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert '10 January 1998' == \
           pclearance_application_proof_object['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert '123-45-6789' == \
           pclearance_application_proof_object['requested_proof']['revealed_attrs']['attr4_referent']['raw']

    assert 'Sylhet' == pclearance_application_proof_object['requested_proof']['self_attested_attrs']['attr5_referent']

    assert await anoncreds.verifier_verify_proof(policestation['pclearance_application_proof_request'], policestation['pclearance_application_proof'],
                                                 policestation['schemas_for_pclearance_application'],
                                                 policestation['cred_defs_for_pclearance_application'],
                                                 policestation['revoc_ref_defs_for_pclearance_application'],
                                                 policestation['revoc_regs_for_pclearance_application'])


    #======================= Step 5.3 (Police Clearance ) Credential ==================
    #---------------------------------------------------------------------------------
    #===================Credential Send and Receive Section ==========================
    #===========>*Police Station  Creates credential offer*<=================

    print("\"The Police Station \" -> Create Police Clearance Credential Offer for Saifur \n")

    policestation['pclearance_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(policestation['wallet'], policestation['pclearance_cred_def_id'])

    print("\"The Police Station \" -> Send  Credential Offer to Saifur \n")
    
    # Over Network 
    saifur['pclearance_cred_offer'] = policestation['pclearance_cred_offer']

    print("Police Clearance Credential Offer (maybe Structure) \n")
    print(saifur['pclearance_cred_offer'])

    # saifur prepares a passportc redential request

    pclearance_cred_offer_object = json.loads(saifur['pclearance_cred_offer'])

    saifur['pclearance_schema_id'] = pclearance_cred_offer_object['schema_id']
    saifur['pclearance_cred_def_id'] = pclearance_cred_offer_object['cred_def_id']
 
    print("\"Saifur\" -> Create and store \"saifur\" Master Secret in Wallet\n")
    #saifur['master_secret_id'] = await anoncreds.prover_create_master_secret(saifur['wallet'], None)

    print("\n\"Saifur\" -> Get  Credential Definition from Ledger \n ")
    (saifur['policestation_pclearance_cred_def_id'], saifur['policestation_pclearance_cred_def']) = \
        await get_cred_def(saifur['pool'], saifur['did'], saifur['pclearance_cred_def_id'])

    print("\"Saifur\" -> Create  Credential Request \n")
    (saifur['pclearance_cred_request'], saifur['pclearance_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(saifur['wallet'], saifur['did'],
                                                     saifur['pclearance_cred_offer'],
                                                     saifur['policestation_pclearance_cred_def'],
                                                     saifur['master_secret_id'])

    print("\"Saifur\" -> Send  Credential Request to the Police Station  \n")

    # Over Network
    policestation['pclearance_cred_request'] = saifur['pclearance_cred_request']


    #Passport issues credential to saifur ----------------
    print("\"The Police Station \" -> Create \"Police Clearance \" Credential for Saifur\n")
    #'attributes': ['name','issue-date','pass_no','status']
    policestation['saifur_pclearance_cred_values'] = json.dumps({
        "name": {"raw": "saifur shmim", "encoded": "113981716457488690172217916278103335"},
        "issue-date": {"raw": "03 May 2021 ", "encoded": "221454313412354"},
        "pass_no": {"raw": "123-45-6789", "encoded": "314141231422543541"},
        "status": {"raw": "clear", "encoded": "15"}
    })
    policestation['pclearance_cred'], _, _ = \
        await anoncreds.issuer_create_credential(policestation['wallet'], policestation['pclearance_cred_offer'],
                                                 policestation['pclearance_cred_request'],
                                                 policestation['saifur_pclearance_cred_values'], None, None)

    print("\"The Police Station \" -> SendCredential to Saifur\n After Assigning Value \n")
    print(policestation['pclearance_cred'])
    # Over the network
    saifur['pclearance_cred'] = policestation['pclearance_cred']

    print("\"Saifur\" -> Store \"P clearance \" Credential from the P-Station ")
    _, saifur['pclearance_cred_def'] = await get_cred_def(saifur['pool'], saifur['did'],
                                                         saifur['pclearance_cred_def_id'])

    await anoncreds.prover_store_credential(saifur['wallet'], None, saifur['pclearance_cred_request_metadata'],
                                            saifur['pclearance_cred'], saifur['pclearance_cred_def'], None)
    
    print("\n\n>>>>>>>>>Stored After Wallet >>>>>>>>>>>>.\n\n", saifur['pclearance_cred_def'])



    #=================Step-6 Show presentation to Visa Center ====================
    # Verifiable Presentation

    # Creating application request (presentaion request) --- validator - visacenter
    print("\n \"Visacenter\" -> Create \"Visa-Application\" Proof Request \n")
    nonce = await anoncreds.generate_nonce()
    visacenter['visa_application_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'visa-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr2_referent': {
                'name': 'last_name',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr3_referent': {
                'name': 'dob',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'expiry',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'passport_no',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': policestation['pclearance_cred_def_id']}]
            },
            'attr7_referent': {
                'name': 'pass_no',
                'restrictions': [{'cred_def_id': policestation['pclearance_cred_def_id']}]
            },
            'attr8_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'adult',
                'p_type': '>=',
                'p_value': 1,
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            }
        }
    })

    print("\"VISA Center\" -> Send Proof Request to Saifur\n")

    # Over Network
    saifur['visa_application_proof_request'] = visacenter['visa_application_proof_request']

    print("proof request\n")
    print(saifur['visa_application_proof_request'])

    # saifur prepares the presentation ===================================

    print("\n\n>>>>>>>>>>Same or Not >>>>>>>>>>>>.\n\n", saifur['visa_application_proof_request'])

    print("\"Saifur\" -> Get credentials for Proof Request")

    search_for_visa_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(saifur['wallet'],
                                                                saifur['visa_application_proof_request'], None)
    
    print("----------Searching(what is the next Value See-->line==637)---------------\n")
    print(search_for_visa_application_proof_request)
    print("----------------------------------\n")

    cred_for_attr1 = await get_credential_for_referent(search_for_visa_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_visa_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_visa_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_visa_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_visa_application_proof_request, 'attr5_referent')
    cred_for_attr6 = await get_credential_for_referent(search_for_visa_application_proof_request, 'attr6_referent')
    cred_for_attr7 = await get_credential_for_referent(search_for_visa_application_proof_request, 'attr7_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_visa_application_proof_request, 'predicate1_referent')
    
    print("-----------cred_for_attr1 = ----------------")
    print(cred_for_attr1)
    print("---------------------------\n")


    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_visa_application_proof_request)

    saifur['creds_for_visa_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_attr5['referent']: cred_for_attr5,
                                                cred_for_attr6['referent']: cred_for_attr6,
                                                cred_for_attr7['referent']: cred_for_attr7,
                                                cred_for_predicate1['referent']: cred_for_predicate1}

    print("+++++++++++++++++++++After Searching(saifur['creds_for_visa_application_proof']) +++++++++++++++++++++++++++++++++++++\n")
    print(saifur['creds_for_visa_application_proof'])

    saifur['schemas_for_visa_application'], saifur['cred_defs_for_visa_application'], \
    saifur['revoc_states_for_visa_application'] = \
        await prover_get_entities_from_ledger(saifur['pool'], saifur['did'],
                                              saifur['creds_for_visa_application_proof'], saifur['name'])

    print("\"--Saifur--\" -> Create \"visa-Application\" Proof\n")
    saifur['visa_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr8_referent': '0122334455'
        },
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
            'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
            'attr6_referent': {'cred_id': cred_for_attr6['referent'], 'revealed': True},
            'attr7_referent': {'cred_id': cred_for_attr7['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    saifur['visa_application_proof'] = \
        await anoncreds.prover_create_proof(saifur['wallet'], saifur['visa_application_proof_request'],
                                            saifur['visa_application_requested_creds'], saifur['master_secret_id'],
                                            saifur['schemas_for_visa_application'],
                                            saifur['cred_defs_for_visa_application'],
                                            saifur['revoc_states_for_visa_application'])
    

    print("\n========== After Proving ======= \n")
    print(saifur['visa_application_proof'])

    print("\n\"Saifur\" -> Send \"visa-Application\" Proof to Visa center\n")

    # Over Network
    visacenter['visa_application_proof'] = saifur['visa_application_proof']
    

    # Validating the verifiable presentation
    visa_application_proof_object = json.loads(visacenter['visa_application_proof'])

    visacenter['schemas_for_visa_application'], visacenter['cred_defs_for_visa_application'], \
    visacenter['revoc_ref_defs_for_visa_application'], visacenter['revoc_regs_for_visa_application'] = \
        await verifier_get_entities_from_ledger(visacenter['pool'], visacenter['did'],
                                                visa_application_proof_object['identifiers'], visacenter['name'])

    print("\"VISA Center \" -> Verify \"VISA-Application\" Proof from Saifur\n")
    assert 'saifur' == \
           visa_application_proof_object['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert 'shamim' == \
           visa_application_proof_object['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert '10 January 1998' == \
           visa_application_proof_object['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert '18 April 2026' == \
           visa_application_proof_object['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
           visa_application_proof_object['requested_proof']['revealed_attrs']['attr5_referent']['raw']
    assert 'clear' == \
           visa_application_proof_object['requested_proof']['revealed_attrs']['attr6_referent']['raw']
    assert '123-45-6789' == \
           visa_application_proof_object['requested_proof']['revealed_attrs']['attr7_referent']['raw']


    assert '0122334455' == visa_application_proof_object['requested_proof']['self_attested_attrs']['attr8_referent']

    assert await anoncreds.verifier_verify_proof(visacenter['visa_application_proof_request'], visacenter['visa_application_proof'],
                                                 visacenter['schemas_for_visa_application'],
                                                 visacenter['cred_defs_for_visa_application'],
                                                 visacenter['revoc_ref_defs_for_visa_application'],
                                                 visacenter['revoc_regs_for_visa_application'])
    



    #======================Step-7 Creating and Storting VISA Credential (after getting visa)===============================
    #-----------------------------------------------Visa credential Creating ------------------------------------------------------------------------------


    print("\"Visa Center \" -> Create \"VISA\" Credential Offer for Saifur\n")

    visacenter['visa_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(visacenter['wallet'], visacenter['visa_cred_def_id'])

    print("\"VISA Center \" -> Send \"VISA\" Credential Offer to saifur\n")
    
    # Over Network 
    saifur['visa_cred_offer'] = visacenter['visa_cred_offer']

    print("After Issuing VISA Cred offer\n")
    print(saifur['visa_cred_offer'])

    # saifur prepares a visa credential request

    visa_cred_offer_object = json.loads(saifur['visa_cred_offer'])

    saifur['visa_schema_id'] = visa_cred_offer_object['schema_id']
    saifur['visa_cred_def_id'] = visa_cred_offer_object['cred_def_id']

    #------------------Creating Master Secret -----------------------------------------
    #===================================================================================
    #---------------------------------------------------------------------------------

    print("\n\n\"Saifur\" -> Create and store \"Saifur\" Master Secret in Wallet")
    #saifur['master_secret_id'] = await anoncreds.prover_create_master_secret(saifur['wallet'], None)

    print("\"Saifur\" -> Get \"visa\" Credential Definition from Ledger\n")
    (saifur['visacenter_visa_cred_def_id'], saifur['visacenter_visa_cred_def']) = \
        await get_cred_def(saifur['pool'], saifur['did'], saifur['visa_cred_def_id'])

    print("\"Saifur\" -> Create \"visa\" Credential Request \n")
    (saifur['visa_cred_request'], saifur['visa_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(saifur['wallet'], saifur['did'],
                                                     saifur['visa_cred_offer'],
                                                     saifur['visacenter_visa_cred_def'],
                                                     saifur['master_secret_id'])

    print("\"Saifur\" -> Send \"VISA \" Credential Request to the VISA Center ")

    # Over Network
    visacenter['visa_cred_request'] = saifur['visa_cred_request']


    #visaCenter issues credential to saifur ----------------
    print("\"VISA Center \" -> Create \"VISA \" Credential for saifur")
     
    #'attributes': ['first_name', 'last_name','expiry', 'visa_no,'type'] 
    visacenter['saifur_visa_cred_values'] = json.dumps({
        "first_name": {"raw": "saifur", "encoded": "113948171645748869017221791627810333"},
        "last_name": {"raw": "shamim", "encoded": "532164278024179012358790245678912345"},
        "visa_no": {"raw": "2050", "encoded": "312414123142254354"},
        "expiry": {"raw": "30 June 2024", "encoded": "221345431341235"},
        "p_no":{"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "type": {"raw": "tourist", "encoded": "541"}
    })
    visacenter['visa_cred'], _, _ = \
        await anoncreds.issuer_create_credential(visacenter['wallet'], visacenter['visa_cred_offer'],
                                                 visacenter['visa_cred_request'],
                                                 visacenter['saifur_visa_cred_values'], None, None)

    print("\"VISA Center \" -> Send \"VISA \" Credential to Saifur\n After visa related value assigning \n")
    print(visacenter['visa_cred'])
    # Over the network
    saifur['visa_cred'] = visacenter['visa_cred']

    print("\"Saifur\" -> Store \"VISA \" Credential from VISA Center \n")
    _, saifur['visa_cred_def'] = await get_cred_def(saifur['pool'], saifur['did'],
                                                         saifur['visa_cred_def_id'])

    await anoncreds.prover_store_credential(saifur['wallet'], None, saifur['visa_cred_request_metadata'],
                                            saifur['visa_cred'], saifur['visa_cred_def'], None)
    
    print("\n\n>>>>>>>>==After Storing>>>>>>>>>>>>>>.\n\n", saifur['visa_cred_def'])

    print("\nVISA Credential Available in Saifur's Wallet \n")

    #====================================-----------------==========================================================
    #===================Step-8 Show Presentation in Immigration ===============================================
    # Verifiable Presentation_2

    # Creating application request (presentaion request) --- validator - immigration

    print("\n \"Immigration\" -> Create  Proof Request \n")
    #=========nonce lagbe kina===========
    nonce = await anoncreds.generate_nonce()
    theimmigration['immigration_application_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'immigration-Application',
        'version': '0.2',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr2_referent': {
                'name': 'last_name',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr3_referent': {
                'name': 'passport_no',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'expiry',
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'first_name',
                'restrictions': [{'cred_def_id': visacenter['visa_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'last_name',
                'restrictions': [{'cred_def_id': visacenter['visa_cred_def_id']}]
            },
            'attr7_referent': {
                'name': 'visa_no',
                'restrictions': [{'cred_def_id': visacenter['visa_cred_def_id']}]
            },
            'attr8_referent': {
                'name': 'expiry',
                'restrictions': [{'cred_def_id': visacenter['visa_cred_def_id']}]
            },
            'attr9_referent': {
                'name': 'p_no',
                'restrictions': [{'cred_def_id': visacenter['visa_cred_def_id']}]
            },
            'attr10_referent': {
                'name': 'type',
                'restrictions': [{'cred_def_id': visacenter['visa_cred_def_id']}]

            },
            'attr11_referent': {
                'name': 'pass_no',
                'restrictions': [{'cred_def_id': policestation['pclearance_cred_def_id']}]
                
            },
            'attr12_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': policestation['pclearance_cred_def_id']}]
                
            },
            'attr13_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'adult',
                'p_type': '>=',
                'p_value': 1,
                'restrictions': [{'cred_def_id': thepassportoffice['passport_cred_def_id']}]
            }
        }
    })

    print("\"Immigration\" -> Send  Proof Request to Saifur\n")

    # Over Network
    saifur['immigration_application_proof_request'] = theimmigration['immigration_application_proof_request']

    print("proof request\n")
    print(saifur['immigration_application_proof_request'])

    # saifur prepares the presentation ===================================

    print("\n\n>>>>>>>>>>Same or Not >>>>>>>>>>>>.\n\n", saifur['immigration_application_proof_request'])

    print("\n Saifur -> Get credentials for \"Immigration\" Proof Request")

    search_for_immigration_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(saifur['wallet'],
                                                                saifur['immigration_application_proof_request'], None)
    
    print("----------Searching(what is next Value See-->line==900)---------------\n")
    print(search_for_immigration_application_proof_request)
    print("----------------------------------\n")

    cred_for_attr1 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr5_referent')
    cred_for_attr6 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr6_referent')
    cred_for_attr7 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr7_referent')
    cred_for_attr8 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr8_referent')
    cred_for_attr9 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr9_referent')
    cred_for_attr10 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr10_referent')
    cred_for_attr11 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr11_referent')
    cred_for_attr12 = await get_credential_for_referent(search_for_immigration_application_proof_request, 'attr12_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_immigration_application_proof_request, 'predicate1_referent')
    
    print("-----------cred_for_attr1 = ----------------")
    print(cred_for_attr1)
    print("---------------------------\n")


    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_immigration_application_proof_request)

    saifur['creds_for_immigration_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_attr5['referent']: cred_for_attr5,
                                                cred_for_attr6['referent']: cred_for_attr6,
                                                cred_for_attr7['referent']: cred_for_attr7,
                                                cred_for_attr8['referent']: cred_for_attr8,
                                                cred_for_attr9['referent']: cred_for_attr9,
                                                cred_for_attr10['referent']: cred_for_attr10,
                                                cred_for_attr11['referent']: cred_for_attr11,
                                                cred_for_attr12['referent']: cred_for_attr12,
                                                cred_for_predicate1['referent']: cred_for_predicate1}

    print("+++++++++++++++++++++After Searching(saifur['creds_for_immigration_application_proof']) +++++++++++++++++++++++++++++++++++++\n")
    print(saifur['creds_for_immigration_application_proof'])

    saifur['schemas_for_immigration_application'], saifur['cred_defs_for_immigration_application'], \
    saifur['revoc_states_for_immigration_application'] = \
        await prover_get_entities_from_ledger(saifur['pool'], saifur['did'],
                                              saifur['creds_for_immigration_application_proof'], saifur['name'])

    print("\"--Saifur--\" -> Create \"Immigration\" Proof\n")
    saifur['immigration_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr13_referent': '0122334455'
        },
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
            'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
            'attr6_referent': {'cred_id': cred_for_attr6['referent'], 'revealed': True},
            'attr7_referent': {'cred_id': cred_for_attr7['referent'], 'revealed': True},
            'attr8_referent': {'cred_id': cred_for_attr8['referent'], 'revealed': True},
            'attr9_referent': {'cred_id': cred_for_attr9['referent'], 'revealed': True},
            'attr10_referent': {'cred_id': cred_for_attr10['referent'], 'revealed': True},
            'attr11_referent': {'cred_id': cred_for_attr11['referent'], 'revealed': True},
            'attr12_referent': {'cred_id': cred_for_attr12['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    saifur['immigration_application_proof'] = \
        await anoncreds.prover_create_proof(saifur['wallet'], saifur['immigration_application_proof_request'],
                                            saifur['immigration_application_requested_creds'], saifur['master_secret_id'],
                                            saifur['schemas_for_immigration_application'],
                                            saifur['cred_defs_for_immigration_application'],
                                            saifur['revoc_states_for_immigration_application'])
    print("\n========== After Proving ======= \n")
    print(saifur['immigration_application_proof'])


    print("\n\"Saifur\" -> Send \"Immigration\" Proof to Immigration\n")

    # Over Network
    theimmigration['immigration_application_proof'] = saifur['immigration_application_proof']

                                       

    # Validating the verifiable presentation
    immigration_application_proof_object = json.loads(theimmigration['immigration_application_proof'])

    theimmigration['schemas_for_immigration_application'], theimmigration['cred_defs_for_immigration_application'], \
    theimmigration['revoc_ref_defs_for_immigration_application'], theimmigration['revoc_regs_for_immigration_application'] = \
       await verifier_get_entities_from_ledger(theimmigration['pool'], theimmigration['did'],
                                               immigration_application_proof_object['identifiers'], theimmigration['name'])

    print("\"Immigration\" -> Verify  Proof from Saifur\n")

    assert 'saifur' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert 'shamim' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert '123-45-6789' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert '18 April 2026' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert 'saifur' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr5_referent']['raw']
    assert 'shamim' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr6_referent']['raw']
    assert '2050' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr7_referent']['raw']
    assert '30 June 2024' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr8_referent']['raw']
    assert '123-45-6789' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr9_referent']['raw']
    assert 'tourist' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr10_referent']['raw']
    assert '123-45-6789' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr11_referent']['raw']
    assert 'clear' == \
           immigration_application_proof_object['requested_proof']['revealed_attrs']['attr12_referent']['raw']
    assert '0122334455' == immigration_application_proof_object['requested_proof']['self_attested_attrs']['attr13_referent']


    assert await anoncreds.verifier_verify_proof(theimmigration['immigration_application_proof_request'], theimmigration['immigration_application_proof'],
                                                 theimmigration['schemas_for_immigration_application'],
                                                 theimmigration['cred_defs_for_immigration_application'],
                                                 theimmigration['revoc_ref_defs_for_immigration_application'],
                                                 theimmigration['revoc_regs_for_immigration_application'])
    
    #======================Step-9 Creating and Storting Immigration Credential (after checking immigration)===============================
    #-----------------------------------------------Immigration Credential Creating ------------------------------------------------------------------------------


    print("\"Immigration \" -> Create Credential offer for Saifur\n")

    theimmigration['immigration_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(theimmigration['wallet'], theimmigration['immigration_cred_def_id'])

    print("\"Immigration \" -> Send Credential Offer to Saifur\n")
    
    # Over Network 
    saifur['immigration_cred_offer'] = theimmigration['immigration_cred_offer']

    print("After Issuing Immigration Cred offer\n")
    print(saifur['immigration_cred_offer'])

    # saifur prepares a credential request to immigration

    immigration_cred_offer_object = json.loads(saifur['immigration_cred_offer'])

    saifur['immigration_schema_id'] = immigration_cred_offer_object['schema_id']
    saifur['immigration_cred_def_id'] = immigration_cred_offer_object['cred_def_id']

    #------------------Creating Master Secret -----------------------------------------
    #===================================================================================
    #---------------------------------------------------------------------------------

    print("\n\n\"Saifur\" -> Create and store Master Secret in Wallet")
    #saifur['master_secret_id'] = await anoncreds.prover_create_master_secret(saifur['wallet'], None)

    print("\"Saifur\" -> Get Immigration Credential Definition from Ledger\n")
    (saifur['theimmigration_immigration_cred_def_id'], saifur['theimmigration_immigration_cred_def']) = \
        await get_cred_def(saifur['pool'], saifur['did'], saifur['immigration_cred_def_id'])

    print("\"Saifur\" -> Create  Credential Request  to Immigration \n")
    (saifur['immigration_cred_request'], saifur['immigration_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(saifur['wallet'], saifur['did'],
                                                     saifur['immigration_cred_offer'],
                                                     saifur['theimmigration_immigration_cred_def'],
                                                     saifur['master_secret_id'])

    print("\"Saifur\" -> Send Credential Request to the Immigration ")

    # Over Network
    theimmigration['immigration_cred_request'] = saifur['immigration_cred_request']


    #immigration issues credential to saifur ----------------
    print("\"Immigration \" -> Create  Credential for Saifur")
     
    #'attributes': ['first_name', 'last_name','passport_no','visa_no','type', 'date']
    
    theimmigration['saifur_immigration_cred_values'] = json.dumps({
        "first_name": {"raw": "saifur", "encoded": "11394817164574869017221791627810333"},
        "last_name": {"raw": "shamim", "encoded": "53216427802417012358790245678912345"},
        "passport_no":{"raw": "123-45-6789", "encoded": "3124141931422543541"},
        "visa_no": {"raw": "2050", "encoded": "312414123142254354"},
        "type": {"raw": "Exit", "encoded": "841"},
        "date": {"raw": "02 February 2024 ", "encoded": "31241412314254354"}
    })
    theimmigration['immigration_cred'], _, _ = \
        await anoncreds.issuer_create_credential(theimmigration['wallet'], theimmigration['immigration_cred_offer'],
                                                 theimmigration['immigration_cred_request'],
                                                 theimmigration['saifur_immigration_cred_values'], None, None)

    print("\"Immigration \" -> Send Credential to Saifur\n After assigning the Immigration related value  \n")
    print(theimmigration['immigration_cred'])

    # Over the network
    saifur['immigration_cred'] = theimmigration['immigration_cred']

    print("\"Saifur\" -> Store Credential from The Immigration \n")
    _, saifur['immigration_cred_def'] = await get_cred_def(saifur['pool'], saifur['did'],
                                                         saifur['immigration_cred_def_id'])

    await anoncreds.prover_store_credential(saifur['wallet'], None, saifur['immigration_cred_request_metadata'],
                                            saifur['immigration_cred'], saifur['immigration_cred_def'], None)
    
    print("\n\n>>>>>>>>==After Storing>>>>>>>>>>>>>>.\n\n", saifur['immigration_cred_def'])

    print("\nImmigration Credential Available in Saifur's Wallet \n")


    print("\n\n=========> Finished <==========\n")


loop = asyncio.get_event_loop()
loop.run_until_complete(run())