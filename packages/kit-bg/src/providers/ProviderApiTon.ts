/* eslint-disable @typescript-eslint/no-unused-vars */
import { web3Errors } from '@onekeyfe/cross-inpage-provider-errors';
import { IInjectedProviderNames } from '@onekeyfe/cross-inpage-provider-types';
import BigNumber from 'bignumber.js';
import TonWeb from 'tonweb';

import type { IEncodedTxTon } from '@onekeyhq/core/src/chains/ton/types';
import {
  backgroundClass,
  permissionRequired,
  providerApiMethod,
} from '@onekeyhq/shared/src/background/backgroundDecorators';
import platformEnv from '@onekeyhq/shared/src/platformEnv';
import type { INetworkAccount } from '@onekeyhq/shared/types/account';

import {
  getAccountVersion,
  getWalletContractInstance,
} from '../vaults/impls/ton/sdkTon/utils';

import ProviderApiBase from './ProviderApiBase';

import type { IProviderBaseBackgroundNotifyInfo } from './ProviderApiBase';
import type {
  SignDataPayload,
  TransactionPayload,
} from '@onekeyfe/cross-inpage-provider-ton/dist/types';
import type { IJsBridgeMessagePayload } from '@onekeyfe/cross-inpage-provider-types';

enum ENetwork {
  Mainnet = '-239',
  Testnet = '-3',
}

@backgroundClass()
class ProviderApiTon extends ProviderApiBase {
  public providerName = IInjectedProviderNames.ton;

  private async _getAccount(request: IJsBridgeMessagePayload) {
    const accounts = await this.getAccountsInfo(request);
    return accounts[0];
  }

  public override notifyDappAccountsChanged(
    info: IProviderBaseBackgroundNotifyInfo,
  ) {
    const data = async () => {
      const accounts =
        await this.backgroundApi.serviceDApp.dAppGetConnectedAccountsInfo({
          origin: info.targetOrigin,
          scope: this.providerName,
        });
      let params;
      try {
        if (accounts && accounts.length > 0) {
          params = this._getAccountResponse(accounts[0].account);
        }
      } catch {
        // ignore
      }
      const result = {
        method: 'wallet_events_accountChanged',
        params,
      };
      return result;
    };
    info.send(data, info.targetOrigin);
  }

  public override notifyDappChainChanged(
    info: IProviderBaseBackgroundNotifyInfo,
  ) {
    const data = async () => {
      const accounts =
        await this.backgroundApi.serviceDApp.dAppGetConnectedAccountsInfo({
          origin: info.targetOrigin,
          scope: this.providerName,
        });
      const result = {
        method: 'wallet_events_networkChange',
        params: accounts ? accounts[0].accountInfo?.networkId : undefined,
      };
      return result;
    };
    info.send(data, info.targetOrigin);
    this.notifyNetworkChangedToDappSite(info.targetOrigin);
  }

  public rpcCall() {
    throw web3Errors.rpc.methodNotSupported();
  }

  @providerApiMethod()
  public async connect(request: IJsBridgeMessagePayload, params: string[]) {
    let accounts =
      await this.backgroundApi.serviceDApp.dAppGetConnectedAccountsInfo(
        request,
      );
    if (!accounts || accounts.length === 0) {
      await this.backgroundApi.serviceDApp.openConnectionModal(request);
      accounts = await this.getAccountsInfo(request);
    }
    return this._getAccountResponse(accounts[0].account);
  }

  @providerApiMethod()
  public async disconnect(request: IJsBridgeMessagePayload) {
    const { origin } = request;
    if (!origin) {
      return;
    }
    await this.backgroundApi.serviceDApp.disconnectWebsite({
      origin,
      storageType: 'injectedProvider',
    });
  }

  @providerApiMethod()
  public async getDeviceInfo(request: IJsBridgeMessagePayload) {
    return {
      appName: 'OneKey',
      appVersion: platformEnv.version,
      maxProtocolVersion: 2,
      features: [
        { name: 'SendTransaction', maxMessages: 4 },
        { name: 'SignData' },
      ],
    };
  }

  private async _getAccountResponse(account: INetworkAccount) {
    const version = getAccountVersion(account.id);
    if (!account.pub) {
      throw new Error('Invalid account');
    }
    const wallet = getWalletContractInstance({
      version,
      publicKey: account.pub,
      backgroundApi: this.backgroundApi,
    });
    const deploy = await wallet.createStateInit();
    return {
      address: account.addressDetail.baseAddress,
      network: ENetwork.Mainnet,
      publicKey: account.pub,
      walletStateInit: Buffer.from(await deploy.stateInit.toBoc()).toString(
        'base64',
      ),
    };
  }

  @permissionRequired()
  @providerApiMethod()
  public async sendTransaction(
    request: IJsBridgeMessagePayload,
    params: [TransactionPayload],
  ): Promise<any> {
    const accounts = await this.getAccountsInfo(request);
    const account = accounts[0];
    const tx = params[0];
    if (tx.from) {
      const fromAddr = new TonWeb.Address(tx.from);
      if (fromAddr.toString() !== account.account.addressDetail.baseAddress) {
        throw new Error('Invalid from address');
      }
    }
    const encodedTx: IEncodedTxTon = {
      fromAddress: tx.from || account.account.addressDetail.displayAddress,
      sequenceNo: 0,
      messages: tx.messages.map((m) => ({
        toAddress: m.address,
        amount: new BigNumber(m.amount),
        payload: m.payload
          ? Buffer.from(m.payload, 'base64').toString('hex')
          : undefined,
        stateInit: m.stateInit
          ? Buffer.from(m.stateInit, 'base64').toString('hex')
          : undefined,
      })),
      expireAt: tx.valid_until,
    };
    const result =
      await this.backgroundApi.serviceDApp.openSignAndSendTransactionModal({
        request,
        encodedTx,
        networkId: account.accountInfo?.networkId ?? '',
        accountId: account?.account.id ?? '',
        signOnly: true,
      });

    return result.txid;
  }

  @permissionRequired()
  @providerApiMethod()
  public async signData(
    request: IJsBridgeMessagePayload,
    params: [SignDataPayload],
  ): Promise<any> {
    const accounts = await this.getAccountsInfo(request);
    const account = accounts[0];
    const data = params[0];
    const timestamp = Math.floor(Date.now() / 1000);
    const result = await this.backgroundApi.serviceDApp.openSignMessageModal({
      request,
      networkId: account?.accountInfo?.networkId ?? '',
      accountId: account?.account.id ?? '',
      unsignedMessage: {
        message: data.cell,
        payload: {
          schemaCrc: data.schema_crc,
          timestamp,
        },
      },
    });

    return result;
  }
}

export default ProviderApiTon;
