import { ActionList, IconButton } from '@onekeyhq/components/src/actions';
import type { IActionListSection } from '@onekeyhq/components/src/actions';
import {
  Icon,
  Image,
  SizableText,
  Skeleton,
  XStack,
  YStack,
} from '@onekeyhq/components/src/primitives';
import type { IKeyOfIcons, Stack } from '@onekeyhq/components/src/primitives';

import type { Animated, StyleProp, ViewStyle } from 'react-native';
import type { AvatarImage, GetProps } from 'tamagui';

export interface IDesktopTabItemProps {
  icon?: IKeyOfIcons;
  showAvatar?: boolean;
  avatarSrc?: GetProps<typeof AvatarImage>['src'];
  label?: string;
  selected?: boolean;
  tabBarStyle?: Animated.WithAnimatedValue<StyleProp<ViewStyle>>;
  actionList?: IActionListSection[];
}

export function DesktopTabItem(
  props: IDesktopTabItemProps & GetProps<typeof Stack>,
) {
  const {
    icon,
    label,
    selected,
    tabBarStyle,
    actionList,
    avatarSrc,
    showAvatar = false,
    ...rest
  } = props;
  return (
    <YStack testID={rest.testID}>
      <XStack
        alignItems="center"
        py="$1.5"
        $gtMd={{
          flexDirection: 'row',
          px: '$2',
          bg: selected ? '$bgActive' : undefined,
          borderRadius: '$2',
        }}
        userSelect="none"
        style={tabBarStyle as ViewStyle}
        {...(!selected && {
          hoverStyle: {
            bg: '$bgHover',
          },
          pressStyle: {
            bg: '$bgActive',
          },
        })}
        {...rest}
        testID={
          selected
            ? `tab-modal-active-item-${rest.id || ''}`
            : `tab-modal-no-active-item-${rest.id || ''}`
        }
      >
        {icon ? (
          <Icon
            flexShrink={0}
            name={icon}
            color={selected ? '$iconActive' : '$iconSubdued'}
            size="$5"
          />
        ) : null}
        {showAvatar ? (
          <Image borderRadius="$1" size="$4.5" m="$px">
            {avatarSrc ? <Image.Source src={avatarSrc} /> : null}
            <Image.Fallback bg="$bgSidebar">
              <Icon
                size="$4.5"
                name="GlobusOutline"
                color={selected ? '$iconActive' : '$iconSubdued'}
              />
            </Image.Fallback>
            {avatarSrc ? (
              <Image.Loading>
                <Skeleton width="100%" height="100%" />
              </Image.Loading>
            ) : null}
          </Image>
        ) : null}
        {label ? (
          <SizableText
            flex={1}
            numberOfLines={1}
            mx="$2"
            color="$text"
            size="$bodyMd"
          >
            {label}
          </SizableText>
        ) : null}
        {actionList ? (
          <ActionList
            title=""
            placement="right-start"
            renderTrigger={
              selected ? (
                <IconButton
                  size="small"
                  icon="DotHorOutline"
                  variant="tertiary"
                  focusVisibleStyle={undefined}
                  p="$0.5"
                  m={-3}
                  testID="browser-bar-options"
                />
              ) : null
            }
            sections={actionList}
          />
        ) : null}
      </XStack>
    </YStack>
  );
}
