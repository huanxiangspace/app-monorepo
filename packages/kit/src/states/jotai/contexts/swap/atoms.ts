import BigNumber from 'bignumber.js';
import { isNil } from 'lodash';

import { getNetworkIdsMap } from '@onekeyhq/shared/src/config/networkIds';
import { dangerAllNetworkRepresent } from '@onekeyhq/shared/src/config/presetNetworks';
import {
  ESwapProviderSort,
  swapSlippageAutoValue,
} from '@onekeyhq/shared/types/swap/SwapProvider.constants';
import {
  ESwapReceiveAddressType,
  ESwapSlippageSegmentKey,
} from '@onekeyhq/shared/types/swap/types';
import type {
  ESwapDirectionType,
  ESwapRateDifferenceUnit,
  IFetchQuoteResult,
  ISwapAlertState,
  ISwapAutoSlippageSuggestedValue,
  ISwapNetwork,
  ISwapSlippageSegmentItem,
  ISwapToken,
  ISwapTokenCatch,
} from '@onekeyhq/shared/types/swap/types';

import { createJotaiContext } from '../../utils/createJotaiContext';

import type { IAccountSelectorActiveAccountInfo } from '../accountSelector';

const {
  Provider: ProviderJotaiContextSwap,
  contextAtom,
  contextAtomComputed,
  contextAtomMethod,
} = createJotaiContext();
export { ProviderJotaiContextSwap, contextAtomMethod };

// swap networks & tokens
export const { atom: swapNetworks, use: useSwapNetworksAtom } = contextAtom<
  ISwapNetwork[]
>([]);

export const {
  atom: swapNetworksIncludeAllNetworkAtom,
  use: useSwapNetworksIncludeAllNetworkAtom,
} = contextAtomComputed<ISwapNetwork[]>((get) => {
  const networks = get(swapNetworks());
  const allNetwork = {
    networkId: getNetworkIdsMap().onekeyall,
    name: dangerAllNetworkRepresent.name,
    symbol: dangerAllNetworkRepresent.symbol,
    logoURI: dangerAllNetworkRepresent.logoURI,
    shortcode: dangerAllNetworkRepresent.shortcode,
    isAllNetworks: true,
  };
  return [allNetwork, ...networks];
});

export const { atom: swapTokenMapAtom, use: useSwapTokenMapAtom } =
  contextAtom<{
    updatedAt: number;
    tokenCatch?: Record<string, ISwapTokenCatch>;
  }>({
    updatedAt: 0,
  });

export const { atom: swapTokenFetchingAtom, use: useSwapTokenFetchingAtom } =
  contextAtom<boolean>(false);

// swap account
export const {
  atom: swapToAnotherAccountAddressAtom,
  use: useSwapToAnotherAccountAddressAtom,
} = contextAtom<{
  networkId: string | undefined;
  address: string | undefined;
  accountInfo: IAccountSelectorActiveAccountInfo | undefined;
}>({ networkId: undefined, address: undefined, accountInfo: undefined });

// swap select token
export const {
  atom: swapSelectFromTokenAtom,
  use: useSwapSelectFromTokenAtom,
} = contextAtom<ISwapToken | undefined>(undefined);

export const { atom: swapSelectToTokenAtom, use: useSwapSelectToTokenAtom } =
  contextAtom<ISwapToken | undefined>(undefined);

export const {
  atom: swapSwapModalSelectFromTokenAtom,
  use: useSwapModalSelectFromTokenAtom,
} = contextAtom<ISwapToken | undefined>(undefined);

export const {
  atom: swapSwapModalSelectToTokenAtom,
  use: useSwapModalSelectToTokenAtom,
} = contextAtom<ISwapToken | undefined>(undefined);

export const {
  atom: swapFromTokenAmountAtom,
  use: useSwapFromTokenAmountAtom,
} = contextAtom<string>('');

export const {
  atom: swapSelectedFromTokenBalanceAtom,
  use: useSwapSelectedFromTokenBalanceAtom,
} = contextAtom('');

export const {
  atom: swapSelectedToTokenBalanceAtom,
  use: useSwapSelectedToTokenBalanceAtom,
} = contextAtom('');

export const {
  atom: swapAllNetworkTokenListMapAtom,
  use: useSwapAllNetworkTokenListMapAtom,
} = contextAtom<Record<string, ISwapToken[]>>({});

export const {
  atom: swapAllNetworkActionLockAtom,
  use: useSwapAllNetworkActionLockAtom,
} = contextAtom<boolean>(false);

// swap quote
export const {
  atom: swapManualSelectQuoteProvidersAtom,
  use: useSwapManualSelectQuoteProvidersAtom,
} = contextAtom<IFetchQuoteResult | undefined>(undefined);

export const { atom: swapQuoteListAtom, use: useSwapQuoteListAtom } =
  contextAtom<IFetchQuoteResult[]>([]);

export const { atom: swapProviderSortAtom, use: useSwapProviderSortAtom } =
  contextAtom<ESwapProviderSort>(ESwapProviderSort.RECOMMENDED);

export const {
  atom: swapQuoteActionLockAtom,
  use: useSwapQuoteActionLockAtom,
} = contextAtom<{
  actionLock: boolean;
  fromToken?: ISwapToken;
  toToken?: ISwapToken;
  fromTokenAmount?: string;
  accountId?: string;
  address?: string;
}>({ actionLock: false });

export const {
  atom: swapQuoteIntervalCountAtom,
  use: useSwapQuoteIntervalCountAtom,
} = contextAtom<number>(0);

export const {
  atom: swapQuoteEventTotalCountAtom,
  use: useSwapQuoteEventTotalCountAtom,
} = contextAtom<number>(0);

export const {
  atom: swapShouldRefreshQuoteAtom,
  use: useSwapShouldRefreshQuoteAtom,
} = contextAtom<boolean>(false);

export const {
  atom: swapSortedQuoteListAtom,
  use: useSwapSortedQuoteListAtom,
} = contextAtomComputed<IFetchQuoteResult[]>((get) => {
  const list = get(swapQuoteListAtom());
  const fromTokenAmount = get(swapFromTokenAmountAtom());
  const fromTokenAmountBN = new BigNumber(fromTokenAmount);
  const sortType = get(swapProviderSortAtom());
  const resetList: IFetchQuoteResult[] = list.map(
    (item: IFetchQuoteResult) => ({
      ...item,
      receivedBest: false,
      isBest: false,
      minGasCost: false,
    }),
  );
  let sortedList = [...resetList];
  const gasFeeSorted = resetList.slice().sort((a, b) => {
    const aBig = new BigNumber(a.fee?.estimatedFeeFiatValue || Infinity);
    const bBig = new BigNumber(b.fee?.estimatedFeeFiatValue || Infinity);
    return aBig.comparedTo(bBig);
  });
  if (sortType === ESwapProviderSort.GAS_FEE) {
    sortedList = [...gasFeeSorted];
  }
  if (sortType === ESwapProviderSort.SWAP_DURATION) {
    sortedList = resetList.slice().sort((a, b) => {
      const aVal = new BigNumber(a.estimatedTime || Infinity);
      const bVal = new BigNumber(b.estimatedTime || Infinity);
      return aVal.comparedTo(bVal);
    });
  }
  const receivedSorted = resetList.slice().sort((a, b) => {
    const aVal = new BigNumber(a.toAmount || 0);
    const bVal = new BigNumber(b.toAmount || 0);
    // Check if limit exists for a and b
    const aHasLimit = !!a.limit;
    const bHasLimit = !!b.limit;

    if (aVal.isZero() && bVal.isZero() && aHasLimit && !bHasLimit) {
      return -1;
    }

    if (aVal.isZero() && bVal.isZero() && bHasLimit && !aHasLimit) {
      return 1;
    }

    if (
      aVal.isZero() ||
      aVal.isNaN() ||
      fromTokenAmountBN.lt(new BigNumber(a.limit?.min || 0)) ||
      fromTokenAmountBN.gt(new BigNumber(a.limit?.max || Infinity))
    ) {
      return 1;
    }
    if (
      bVal.isZero() ||
      bVal.isNaN() ||
      fromTokenAmountBN.lt(new BigNumber(b.limit?.min || 0)) ||
      fromTokenAmountBN.gt(new BigNumber(b.limit?.max || Infinity))
    ) {
      return -1;
    }
    return bVal.comparedTo(aVal);
  });
  if (
    sortType === ESwapProviderSort.RECOMMENDED ||
    sortType === ESwapProviderSort.RECEIVED
  ) {
    sortedList = [...receivedSorted];
  }
  return sortedList.map((p) => {
    if (
      p.info.provider === receivedSorted?.[0]?.info?.provider &&
      p.info.providerName === receivedSorted?.[0]?.info?.providerName &&
      p.toAmount
    ) {
      p.receivedBest = true;
      p.isBest = true;
    }
    if (
      p.info.provider === gasFeeSorted?.[0]?.info?.provider &&
      p.info.providerName === gasFeeSorted?.[0]?.info?.providerName &&
      p.toAmount
    ) {
      p.minGasCost = true;
    }
    return p;
  });
});

export const {
  atom: swapQuoteCurrentSelectAtom,
  use: useSwapQuoteCurrentSelectAtom,
} = contextAtomComputed((get) => {
  const list = get(swapSortedQuoteListAtom());
  const manualSelectQuoteProviders = get(swapManualSelectQuoteProvidersAtom());
  const manualSelectQuoteResult = list.find(
    (item) =>
      item.info.provider === manualSelectQuoteProviders?.info.provider &&
      item.info.providerName === manualSelectQuoteProviders?.info.providerName,
  );
  if (manualSelectQuoteProviders && manualSelectQuoteResult?.toAmount) {
    return list.find(
      (item) =>
        item.info.provider === manualSelectQuoteProviders.info.provider &&
        item.info.providerName === manualSelectQuoteProviders.info.providerName,
    );
  }
  if (list?.length > 0) {
    return list[0];
  }
  return undefined;
});

export const { atom: swapQuoteFetchingAtom, use: useSwapQuoteFetchingAtom } =
  contextAtom<boolean>(false);

export const {
  atom: swapSelectTokenDetailFetchingAtom,
  use: useSwapSelectTokenDetailFetchingAtom,
} = contextAtom<Record<ESwapDirectionType, boolean>>({
  'from': false,
  'to': false,
});

export const {
  atom: swapSilenceQuoteLoading,
  use: useSwapSilenceQuoteLoading,
} = contextAtom<boolean>(false);

export const {
  atom: swapProviderSupportReceiveAddressAtom,
  use: useSwapProviderSupportReceiveAddressAtom,
} = contextAtomComputed((get) => {
  const quoteResult = get(swapQuoteCurrentSelectAtom());
  if (!quoteResult) {
    return true;
  }
  return (
    !quoteResult.unSupportReceiveAddressDifferent && !quoteResult.isWrapped
  );
});

// swap state
export const { atom: swapAlertsAtom, use: useSwapAlertsAtom } = contextAtom<{
  states: ISwapAlertState[];
  quoteId: string;
}>({ states: [], quoteId: '' });

export const { atom: rateDifferenceAtom, use: useRateDifferenceAtom } =
  contextAtom<{ value: string; unit: ESwapRateDifferenceUnit } | undefined>(
    undefined,
  );

// swap approve
export const {
  atom: swapQuoteApproveAllowanceUnLimitAtom,
  use: useSwapQuoteApproveAllowanceUnLimitAtom,
} = contextAtom<boolean>(false);

export const {
  atom: swapApproveAllowanceSelectOpenAtom,
  use: useSwapApproveAllowanceSelectOpenAtom,
} = contextAtom<boolean>(false);

// swap slippage

export const {
  atom: swapSlippagePercentageModeAtom,
  use: useSwapSlippagePercentageModeAtom,
} = contextAtom<ESwapSlippageSegmentKey>(ESwapSlippageSegmentKey.AUTO);

export const {
  atom: swapAutoSlippageSuggestedValueAtom,
  use: useSwapAutoSlippageSuggestedValueAtom,
} = contextAtom<ISwapAutoSlippageSuggestedValue | undefined>(undefined);

export const {
  atom: swapSlippagePercentageCustomValueAtom,
  use: useSwapSlippagePercentageCustomValueAtom,
} = contextAtom<number>(swapSlippageAutoValue);

export const {
  atom: swapSlippagePercentageAtom,
  use: useSwapSlippagePercentageAtom,
} = contextAtomComputed<{
  slippageItem: ISwapSlippageSegmentItem;
  autoValue: number;
}>((get) => {
  const mode = get(swapSlippagePercentageModeAtom());
  const quoteResult = get(swapQuoteCurrentSelectAtom());
  let autoValue = swapSlippageAutoValue;
  let value = swapSlippageAutoValue;
  if (!isNil(quoteResult?.autoSuggestedSlippage)) {
    autoValue = quoteResult.autoSuggestedSlippage;
  }
  if (mode === ESwapSlippageSegmentKey.AUTO) {
    value = autoValue;
  } else {
    value = get(swapSlippagePercentageCustomValueAtom());
  }
  return {
    slippageItem: {
      key: mode,
      value,
    },
    autoValue,
  };
});

export const {
  atom: swapSlippageDialogOpeningAtom,
  use: useSwapSlippageDialogOpeningAtom,
} = contextAtom<{ status: boolean; flag?: string }>({ status: false });

// swap build_tx
export const {
  atom: swapBuildTxFetchingAtom,
  use: useSwapBuildTxFetchingAtom,
} = contextAtom<boolean>(false);

// swap receiver address
export const {
  atom: swapReceiverAddressTypeAtom,
  use: useSwapReceiverAddressTypeAtom,
} = contextAtom<ESwapReceiveAddressType>(ESwapReceiveAddressType.USER_ACCOUNT);

export const {
  atom: swapReceiverAddressInputValueAtom,
  use: useSwapReceiverAddressInputValueAtom,
} = contextAtom<string>('');

export const {
  atom: swapReceiverAddressBookValueAtom,
  use: useSwapReceiverAddressBookValueAtom,
} = contextAtom<string>('');
