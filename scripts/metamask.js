const detectEthereumProvider = require('@metamask/detect-provider');
const isMetamaskInstalled = async () => {
    const provider = await detectEthereumProvider();
    console.log('isMetamaskInstalled', provider);
    return provider;
}
