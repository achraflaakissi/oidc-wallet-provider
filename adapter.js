
const { DynamoDB } = require('aws-sdk');
const TABLE_NAME = 'oidc-provider';
const TABLE_REGION = 'us-east-1';
const dynamoClient = new DynamoDB.DocumentClient({
    region: TABLE_REGION,
});
class DynamoDBAdapter {
    constructor(name) {
        this.name = name;
    }
    async upsert(id, payload, expiresIn) {
        // DynamoDB can recognise TTL values only in seconds
        const expiresAt = expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : null;
        const params = {
            TableName: TABLE_NAME,
            Key: { modelId: this.name + "-" + id },
            UpdateExpression: "SET payload = :payload" +
                (expiresAt ? ", expiresAt = :expiresAt" : "") +
                (payload.userCode ? ", userCode = :userCode" : "") +
                (payload.uid ? ", uid = :uid" : "") +
                (payload.grantId ? ", grantId = :grantId" : ""),
            ExpressionAttributeValues: Object.assign(Object.assign(Object.assign(Object.assign({ ":payload": payload }, (expiresAt ? { ":expiresAt": expiresAt } : {})), (payload.userCode ? { ":userCode": payload.userCode } : {})), (payload.uid ? { ":uid": payload.uid } : {})), (payload.grantId ? { ":grantId": payload.grantId } : {})),
        };
        await dynamoClient.update(params).promise();
    }
    async find(id) {
        console.log('this.name + "-" + id', this.name + "-" + id);
        const params = {
            TableName: TABLE_NAME,
            Key: { modelId: this.name + "-" + id },
            ProjectionExpression: "payload, expiresAt",
        };
        const result = ((await dynamoClient.get(params).promise()).Item);
        console.log('result', result);
        // DynamoDB can take upto 48 hours to drop expired items, so a check is required
        if (!result || (result.expiresAt && Date.now() > result.expiresAt * 1000)) {
            return undefined;
        }
        return result.payload;
    }
    async findByUserCode(userCode) {
        var _a;
        const params = {
            TableName: TABLE_NAME,
            IndexName: "userCodeIndex",
            KeyConditionExpression: "userCode = :userCode",
            ExpressionAttributeValues: {
                ":userCode": userCode,
            },
            Limit: 1,
            ProjectionExpression: "payload, expiresAt",
        };
        const result = ((_a = (await dynamoClient.query(params).promise()).Items) === null || _a === void 0 ? void 0 : _a[0]);
        // DynamoDB can take upto 48 hours to drop expired items, so a check is required
        if (!result || (result.expiresAt && Date.now() > result.expiresAt * 1000)) {
            return undefined;
        }
        return result.payload;
    }
    async findByUid(uid) {
        var _a;
        const params = {
            TableName: TABLE_NAME,
            IndexName: "uidIndex",
            KeyConditionExpression: "uid = :uid",
            ExpressionAttributeValues: {
                ":uid": uid,
            },
            Limit: 1,
            ProjectionExpression: "payload, expiresAt",
        };
        const result = ((_a = (await dynamoClient.query(params).promise()).Items) === null || _a === void 0 ? void 0 : _a[0]);
        // DynamoDB can take upto 48 hours to drop expired items, so a check is required
        if (!result || (result.expiresAt && Date.now() > result.expiresAt * 1000)) {
            return undefined;
        }
        return result.payload;
    }
    async consume(id) {
        const params = {
            TableName: TABLE_NAME,
            Key: { modelId: this.name + "-" + id },
            UpdateExpression: "SET #payload.#consumed = :value",
            ExpressionAttributeNames: {
                "#payload": "payload",
                "#consumed": "consumed",
            },
            ExpressionAttributeValues: {
                ":value": Math.floor(Date.now() / 1000),
            },
            ConditionExpression: "attribute_exists(modelId)",
        };
        await dynamoClient.update(params).promise();
    }
    async destroy(id) {
        const params = {
            TableName: TABLE_NAME,
            Key: { modelId: this.name + "-" + id },
        };
        await dynamoClient.delete(params).promise();
    }
    async revokeByGrantId(grantId) {
        let ExclusiveStartKey = undefined;
        do {
            const params = {
                TableName: TABLE_NAME,
                IndexName: "grantIdIndex",
                KeyConditionExpression: "grantId = :grantId",
                ExpressionAttributeValues: {
                    ":grantId": grantId,
                },
                ProjectionExpression: "modelId",
                Limit: 25,
                ExclusiveStartKey,
            };
            const queryResult = await dynamoClient.query(params).promise();
            ExclusiveStartKey = queryResult.LastEvaluatedKey;
            const items = queryResult.Items;
            if (!items || !items.length) {
                return;
            }
            const batchWriteParams = {
                RequestItems: {
                    [TABLE_NAME]: items.reduce((acc, item) => [...acc, { DeleteRequest: { Key: { modelId: item.modelId } } }], []),
                },
            };
            await dynamoClient.batchWrite(batchWriteParams).promise();
        } while (ExclusiveStartKey);
    }
}

module.exports = DynamoDBAdapter;