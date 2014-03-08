Bitcoin.CoinMapping = {
    _mapping: {
        'anoncoin': {
            'networkVersion': 23,
        },
        'bitcoin': {
            'networkVersion': 0
        },
        'bitcoinTestnet': {
            'networkVersion': 111
        },
        'cryptogenicbullion': {
            'networkVersion': 11
        },
        'dogecoin': {
            'networkVersion': 30
        },
        'earthcoin': {
            'networkVersion': 93
        },
        'feathercoin': {
            'networkVersion': 14
        },
        'huntercoin': {
            'networkVersion': 40
        },
        'infinitecoin': {
            'networkVersion': 102
        },
        'ixcoin': {
            'networkVersion': 138
        },
        'litecoin': {
            'networkVersion': 48
        },
        'marscoin': {
            'networkVersion': 50
        },
        'megacoin': {
            'networkVersion': 50
        },
        'memorycoin': {
            'networkVersion': 50
        },
        'namecoin': {
            'networkVersion': 52
        },
        'netcoin': {
            'networkVersion': 112
        },
        'novacoin': {
            'networkVersion': 8
        },
        'peercoin': {
            'networkVersion': 55
        },
        'primecoin': {
            'networkVersion': 23
        },
        'protoshares': {
            'networkVersion': 56
        },
        'quarkcoin': {
            'networkVersion': 58
        },
        'terracoin': {
            'networkVersion': 0
        },
        'vertcoin': {
            'networkVersion': 71
        },
        'worldcoin': {
            'networkVersion': 73
        }

    },
    Change: function(coin) {
        if (typeof this._mapping[coin] == 'undefined') {
            this.Change('bitcoin');
            return false;
        }

        Bitcoin.Address.networkVersion = this._mapping[coin].networkVersion;
        Bitcoin.ECKey.privateKeyPrefix = (this._mapping[coin].networkVersion + 128) % 256;

        return true;
    },
    Name: function(coin) {
        return this._mapping[coin].name || coin.charAt(0).toUpperCase() + coin.slice(1);
    }
}