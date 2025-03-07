import { useCallback, useEffect, useState } from 'react';

import { useIntl } from 'react-intl';

import {
  Icon,
  Image,
  SizableText,
  Skeleton,
  View,
  XStack,
  YStack,
  useMedia,
} from '@onekeyhq/components';
import { AccountAvatar } from '@onekeyhq/kit/src/components/AccountAvatar';
import { Token } from '@onekeyhq/kit/src/components/Token';
import { ETranslations } from '@onekeyhq/shared/src/locale';
import accountUtils from '@onekeyhq/shared/src/utils/accountUtils';

import { useAccountSelectorSyncLoadingAtom } from '../../../states/jotai/contexts/accountSelector';
import {
  useAccountSelectorTrigger,
  useMockAccountSelectorLoading,
} from '../hooks/useAccountSelectorTrigger';

export const AccountSelectorTriggerDappConnection = XStack.styleable<{
  num: number;
  compressionUiMode?: boolean;
  beforeShowTrigger?: () => Promise<void>;
  loadingDuration?: number;
}>(
  (
    {
      num,
      compressionUiMode,
      disabled,
      beforeShowTrigger,
      loadingDuration,
      ...rest
    },
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _: any,
  ) => {
    const { isLoading: mockIsLoading } =
      useMockAccountSelectorLoading(loadingDuration);
    const [syncLoading] = useAccountSelectorSyncLoadingAtom();
    const isLoading = syncLoading?.[num]?.isLoading || mockIsLoading;

    const {
      activeAccount: { account, wallet, indexedAccount },
      showAccountSelector,
    } = useAccountSelectorTrigger({ num, linkNetwork: true });

    const triggerDisabled = isLoading || disabled;

    const handlePress = useCallback(async () => {
      await beforeShowTrigger?.();
      showAccountSelector();
    }, [beforeShowTrigger, showAccountSelector]);

    useEffect(() => {
      console.log('AccountSelectorTriggerDappConnection', ':renderer=====>');
    }, []);

    let addressText = '';
    if (account?.address) {
      addressText = accountUtils.shortenAddress({
        address: account.address || '',
      });
    } else if (!account?.address && account?.addressDetail.isValid) {
      addressText = '';
    } else {
      addressText = 'No Address';
    }

    const accountName = account?.name ? account.name : 'No Account';
    const walletName = wallet?.name ? wallet.name : 'No Wallet';

    const renderAvatar = useCallback(() => {
      if (isLoading) {
        return <Skeleton w="$8" h="$8" />;
      }
      if (account?.address || account?.addressDetail.isValid) {
        return (
          <AccountAvatar
            size="$8"
            borderRadius="$2"
            account={account}
            indexedAccount={indexedAccount}
          />
        );
      }
      return <Icon size="$8" name="XSquareOutline" color="$iconSubdued" />;
    }, [isLoading, account, indexedAccount]);

    const renderWalletAndAccountName = useCallback(() => {
      if (isLoading) {
        return (
          <XStack alignItems="center" h="$5">
            <Skeleton w={118} h={14} />
          </XStack>
        );
      }
      return (
        <XStack>
          <XStack maxWidth="$40">
            <SizableText size="$bodyMd" color="$textSubdued" numberOfLines={1}>
              {walletName}
            </SizableText>
          </XStack>
          <SizableText size="$bodyMd" color="$textSubdued">
            /
          </SizableText>
          <XStack maxWidth="$40">
            <SizableText size="$bodyMd" color="$textSubdued" numberOfLines={1}>
              {accountName}
            </SizableText>
          </XStack>
        </XStack>
      );
    }, [isLoading, accountName, walletName]);
    const renderAddressText = useCallback(() => {
      if (isLoading) {
        return (
          <XStack alignItems="center" h="$5">
            <Skeleton w={196} h={14} />
          </XStack>
        );
      }
      return (
        <SizableText
          flex={1}
          size="$bodyMdMedium"
          numberOfLines={1}
          color="$text"
        >
          {addressText}
        </SizableText>
      );
    }, [isLoading, addressText]);
    return (
      <XStack
        flex={1}
        py="$2"
        px="$3"
        gap="$2"
        bg="$bgApp"
        alignItems="center"
        userSelect="none"
        hoverStyle={
          triggerDisabled
            ? undefined
            : {
                bg: '$bgHover',
              }
        }
        pressStyle={
          triggerDisabled
            ? undefined
            : {
                bg: '$bgActive',
              }
        }
        focusable={!triggerDisabled}
        focusVisibleStyle={
          triggerDisabled
            ? undefined
            : {
                outlineWidth: 2,
                outlineColor: '$focusRing',
                outlineStyle: 'solid',
              }
        }
        borderCurve="continuous"
        onPress={handlePress}
        disabled={triggerDisabled}
        {...rest}
      >
        {renderAvatar()}
        <YStack flex={1}>
          {renderWalletAndAccountName()}
          {renderAddressText()}
        </YStack>
        {triggerDisabled ? null : (
          <Icon
            name="ChevronGrabberVerOutline"
            color="$iconSubdued"
            size="$5"
          />
        )}
      </XStack>
    );
  },
);

export function AccountSelectorTriggerBrowserSingle({ num }: { num: number }) {
  const {
    activeAccount: { account, indexedAccount, wallet },
    showAccountSelector,
  } = useAccountSelectorTrigger({ num, linkNetwork: true });

  const media = useMedia();
  const intl = useIntl();

  const handlePress = useCallback(async () => {
    showAccountSelector();
  }, [showAccountSelector]);

  const accountName = account?.name
    ? account.name
    : intl.formatMessage({
        id: ETranslations.wallet_no_address,
      });

  return (
    <XStack
      role="button"
      p="$1.5"
      borderRadius="$2"
      alignItems="center"
      hoverStyle={{
        bg: '$bgHover',
      }}
      pressStyle={{
        bg: '$bgActive',
      }}
      focusable
      focusVisibleStyle={{
        outlineWidth: 2,
        outlineColor: '$focusRing',
        outlineStyle: 'solid',
      }}
      onPress={handlePress}
      maxWidth="$40"
      minWidth={0}
    >
      <AccountAvatar
        size="small"
        account={account}
        indexedAccount={indexedAccount}
      />
      {media.gtMd ? (
        <>
          <View pl="$2" pr="$1" minWidth={0} maxWidth="$24">
            <SizableText size="$bodySm" color="$textSubdued" numberOfLines={1}>
              {wallet?.name}
            </SizableText>
            <SizableText size="$bodyMdMedium" numberOfLines={1}>
              {accountName}
            </SizableText>
          </View>
          <Icon name="ChevronDownSmallOutline" color="$iconSubdued" size="$5" />
        </>
      ) : null}
    </XStack>
  );
}

export function AccountSelectorTriggerAddressSingle({ num }: { num: number }) {
  const intl = useIntl();
  const {
    activeAccount: { account, network },
    showAccountSelector,
  } = useAccountSelectorTrigger({ num, linkNetwork: true });

  const handlePress = useCallback(async () => {
    showAccountSelector();
  }, [showAccountSelector]);

  const [showNoAddress, setShowNoAddress] = useState(false);

  const addressText = accountUtils.shortenAddress({
    address: account?.address || '',
  });

  useEffect(() => {
    if (!addressText) {
      const timer = setTimeout(() => {
        setShowNoAddress(true);
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [addressText]);

  if (!addressText && !showNoAddress) {
    return <Skeleton width={153} height="$5" />;
  }

  return (
    <XStack
      alignItems="center"
      pl="$1"
      ml="$-1"
      borderRadius="$2"
      hoverStyle={{
        bg: '$bgHover',
      }}
      pressStyle={{
        bg: '$bgActive',
      }}
      focusable
      focusVisibleStyle={{
        outlineWidth: 2,
        outlineColor: '$focusRing',
        outlineStyle: 'solid',
      }}
      onPress={(event) => {
        event.stopPropagation();
        void handlePress();
      }}
      userSelect="none"
    >
      <Image
        width="$4"
        height="$4"
        borderRadius="$full"
        source={{
          uri: network?.logoURI,
        }}
      />
      <SizableText
        pl="$1.5"
        size="$bodyMd"
        color="$textSubdued"
        numberOfLines={1}
      >
        {addressText ||
          (showNoAddress
            ? intl.formatMessage({
                id: ETranslations.wallet_no_address,
              })
            : '')}
      </SizableText>
      <Icon size="$5" color="$iconSubdued" name="ChevronDownSmallOutline" />
    </XStack>
  );
}
