

const assert = require('assert');
const axios = require('axios');


class Account {
  // This interface is required by oidc-provider
  static async findAccount(ctx, id) {
    console.log('interaction', ctx, id)
    // This would ideally be just a check whether the account is still in your storage
    const account = {
      id: id,
      email: id + '@mailtowallet.com',
      email_verified: true,
    };
    if (!account) {
      return undefined;
    }
    return {
      accountId: id,
      // and this claims() method would actually query to retrieve the account claims
      async claims() {
        return {
          sub: id,
          email: account.email,
          email_verified: account.email_verified,
        };
      },
    };
  }

  // This can be anything you need to authenticate a user
  static async authenticate(address, sign, interactionId, nounce) {
    assert(address, 'address must be provided');
    assert(sign, 'sign must be provided');
    assert(interactionId, 'interactionId must be provided');
    assert(nounce, 'nounce must be provided');
    try {
      const data = {
        signedMessage: sign,
        address: address,
        interactionId: interactionId,
        nounce
      }
      const response = await axios.post(`https://v900e2c4ig.execute-api.us-east-1.amazonaws.com/dev/verifySignedMessage`, data);
      const newTodoItem = response.data;
      console.log(`Added a new Todo!`, newTodoItem);
      if (newTodoItem.response) {
        return address;
      } else {
        assert(newTodoItem.response, 'The sign is inccorect');
      }
    } catch (errors) {
      console.error(errors);
      return undefined;
    }
  }
}

module.exports = Account;
