require('dotenv').config()

module.exports = {
  deployments: {
    netId1: {
      eth: {
        instanceAddress: {
          '0.1': '',
          '1': '',
          '100': '',
          '500': '',
          '1000': ''
        },
        symbol: 'ETH',
        decimals: 18
      }
    },
    netId42: {
      eth: {
        instanceAddress: {
          '0.1': '',
          '1': '',
          '100': '',
          '500': '',
          '1000': ''
        },
        symbol: 'ETH',
        decimals: 18
      }
    }
  }
}
