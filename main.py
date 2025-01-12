import random
import requests
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from web3 import Web3
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.rpc.api import Client
from solana.rpc.types import TokenAccountOpts

# Function to generate a random mnemonic phrase
def generate_mnemonic():
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)

# Function to derive addresses for different chains
def derive_address(mnemonic, coin):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    bip44_mst = Bip44.FromSeed(seed, coin)
    bip44_acc = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    return bip44_acc.PublicKey().ToAddress()

# Check balance functions
def check_eth_balance(address):
    infura_url = "https://mainnet.infura.io/v3/b09abd4ea25341d486451a87844628ae"
    web3 = Web3(Web3.HTTPProvider(infura_url))
    balance = web3.eth.get_balance(address)
    return Web3.from_wei(balance, "ether")

def check_btc_balance(address):
    url = f"https://blockchain.info/q/addressbalance/{address}"
    response = requests.get(url)
    if response.status_code == 200:
        balance_satoshi = int(response.text)
        return balance_satoshi / 1e8  # Convert to BTC
    return 0

def check_solana_balance(mnemonic):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    keypair = Keypair.from_seed(seed[:32])
    public_key = keypair.pubkey()
    solana_client = Client("https://api.mainnet-beta.solana.com")
    response = solana_client.get_balance(public_key)
    if response.value is not None:
        return response.value / 1e9  # Convert lamports to SOL
    return 0

# Main brute force function
def brute_force_mnemonic_and_check_balances():
    while True:
        mnemonic = generate_mnemonic()
        print(f"Generated Mnemonic: {mnemonic}")

        # Derive addresses for different chains
        eth_address = derive_address(mnemonic, Bip44Coins.ETHEREUM)
        btc_address = derive_address(mnemonic, Bip44Coins.BITCOIN)

        # Check balances
        eth_balance = check_eth_balance(eth_address)
        btc_balance = check_btc_balance(btc_address)
        sol_balance = check_solana_balance(mnemonic)

        print(f"ETH Address: {eth_address}, Balance: {eth_balance} ETH")
        print(f"BTC Address: {btc_address}, Balance: {btc_balance} BTC")
        print(f"SOL Address: Derived from mnemonic, Balance: {sol_balance} SOL")

        print("\n___________________________________________________________\n")

        if eth_balance > 0 or btc_balance > 0 or sol_balance > 0:
            print("Mnemonic with funds found!", mnemonic)
            break

# Run the brute force function
if __name__ == "__main__":
    brute_force_mnemonic_and_check_balances()
