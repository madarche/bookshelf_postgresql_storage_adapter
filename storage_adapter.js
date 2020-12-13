'use strict';

const Record = require('../model/record');

const PURGE_AFTER_UPSERT_EVERY = 10;
let upsert_count = 0;

// Note: From the author of "oidc-provider" the MongoDB storage adapter is the
// only one that can be considered a reference and that should be used as a
// model.
class StorageAdapter {

    /**
     * Creates an instance of this adapter for an oidc-provider model.
     *
     * @constructor
     * @param {string} name Name of the oidc-provider model. One of "Session", "AccessToken",
     * "AuthorizationCode", "RefreshToken", "ClientCredentials", "Client", "InitialAccessToken",
     * "RegistrationAccessToken", "DeviceCode", "Interaction",
     * "ReplayDetection", or "PushedAuthorizationRequest".
     */
    constructor(name) {
        this.name = name;
    }

    /**
     * Updates or Creates an instance of an oidc-provider model.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error
     *   when encountered.
     * @param {string} id Identifier that oidc-provider will use to reference
     *   this model instance for future operations
     * @param {Object} payload Object with all properties intended for storage
     * @param {number} expiresIn number of seconds intended for this model to be stored
     */
    async upsert(id, payload, expiresIn) {
        // Favoring reads over writes, since the OP is more often called for
        // verifying than for authenticating (the latter implying writes) and do
        // thus performing purgeExpired only when some data is inserted or
        // updated and not when calling "find", "findByUid" or "findByUserCode".
        await this.purgeExpired();

        const update_data = {
            name: this.name,
            data: payload,
        };

        if (expiresIn) {
            update_data.expires_at = new Date(Date.now() + expiresIn * 1000);
        }

        let record = await new Record({id}).fetch();
        if (record) {
            await record.set(update_data).save();
        } else {
            update_data.id = id;
            // It's needed to specify method: 'insert' because we pass an id to
            // the constructor. isNew is true when there is no id. ORM work
            // better when there is no specified id.
            record = await new Record(update_data).save({}, {method: 'insert'});
        }
    }

    /**
     * Returns previously stored instance of an oidc-provider model.
     *
     * @return {Promise} Promise fulfilled with either Object (when found and
     *   not dropped yet due to expiration) or falsy value when not found
     *   anymore. Rejected with error when encountered.
     * @param {string} id Identifier of oidc-provider model
     */
    async find(id) {
        const record = await new Record()
            .query((qb) => {
                qb.where(function() {
                    this.where({id});
                }).andWhere(function() {
                    this.whereNull('expires_at').orWhere('expires_at', '>', new Date());
                });
            })
            .fetch();
        if (!record) {
            return null;
        }

        return record.get('data');
    }

    /**
     * Return previously stored instance of Session by its uid reference property.
     *
     * @return {Promise} Promise fulfilled with the stored session object (when found and not
     * dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
     * when encountered.
     * @param {string} uid the uid value associated with a Session instance
     */
    async findByUid(uid) {
        const record = await new Record()
            .query((qb) => {
                qb.where(function() {
                    this.where('data', '@>', `{"uid": "${uid}"}`);
                }).andWhere(function() {
                    this.whereNull('expires_at').orWhere('expires_at', '>', new Date());
                });
            })
            .fetch();
        if (!record) {
            return null;
        }

        return record.get('data');
    }

    /**
     * Return previously stored instance of DeviceCode by the end-user entered user code.
     * You only need this method for the deviceFlow feature.
     *
     * @param {string} userCode the user_code value associated with a DeviceCode instance
     * @return {Promise} Promise fulfilled with the stored device code object (when found and not
     * dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
     * when encountered.
     *
     */
    async findByUserCode(userCode) {
        const record = await new Record()
            .query((qb) => {
                qb.where(function() {
                    this.where('data', '@>', `{"userCode": "${userCode}"}`);
                }).andWhere(function() {
                    this.whereNull('expires_at').orWhere('expires_at', '>', new Date());
                });
            })
            .fetch();
        if (!record) {
            return null;
        }

        return record.get('data');
    }

    /**
     * Mark a stored oidc-provider model as consumed (not yet expired though!). Future finds for this
     * id should be fulfilled with an object containing additional property named "consumed" with a
     * truthy value (timestamp, date, boolean, etc).
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
     * encountered.
     * @param {string} id Identifier of oidc-provider model
     */
    async consume(id) {
        const record = await new Record({id}).fetch();
        const data = record.get('data');
        data.consumed = new Date().toISOString();
        await record.save({data}, {method: 'update', patch: true});
    }

    /**
     * Destroy/Drop/Remove a stored oidc-provider model. Future finds for this id should be fulfilled
     * with falsy values.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
     * encountered.
     * @param {string} id Identifier of oidc-provider model
     */
    async destroy(id) {
        await new Record({id}).destroy({require: false});
    }

    /**
     * Destroy/Drop/Remove a stored oidc-provider model by its grantId property reference. Future
     * finds for all tokens having this grantId value should be fulfilled with falsy values.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
     * encountered.
     * @param {string} grantId the grantId value associated with a this model's instance
     */
    async revokeByGrantId(grantId) {
        await new Record()
            .where('data', '@>', `{"grantId": "${grantId}"}`)
            .destroy({require: false});
    }

    // *************************************************************************
    // Methods non-required by the oidc-provider framework
    // *************************************************************************

    /**
     * Purges all the records of this oidc-provider model.
     *
     * Commodity method, but not required by the oidc-provider framework.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error
     *   when encountered.
     */
    async purgeExpired() {
        if (++upsert_count < PURGE_AFTER_UPSERT_EVERY) {
            return;
        }
        upsert_count = 0;

        await new Record()
            .where('expires_at', '<=', new Date())
            .destroy({require: false});
    }

    /**
     * Returns all the records of this oidc-provider model.
     *
     * Commodity method, but not required by the oidc-provider framework.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error
     *   when encountered.
     */
    getAll() {
        return new Record()
            .where('name', this.name)
            .orderBy('updated_at', 'desc')
            .fetchAll();
    }

}

module.exports = StorageAdapter;
