import { useAccountData } from '@onekeyhq/kit/src/hooks/useAccountData';
import { InfoItemGroup } from '@onekeyhq/kit/src/views/AssetDetails/pages/HistoryDetails/components/TxDetailsInfoItem';

import { getTxSpecialInfo } from './TxSpecialInfo';

type IProps = {
  accountId: string;
  networkId: string;
};

function TxSpecialInfoContainer(props: IProps) {
  const { accountId, networkId } = props;
  const { network } = useAccountData({ networkId });
  const TxSpecialInfo = getTxSpecialInfo({ impl: network?.impl ?? '' });

  if (TxSpecialInfo) {
    return (
      <InfoItemGroup pt={0} mt="$-2.5">
        <TxSpecialInfo accountId={accountId} networkId={networkId} />
      </InfoItemGroup>
    );
  }

  return null;
}

export { TxSpecialInfoContainer };
