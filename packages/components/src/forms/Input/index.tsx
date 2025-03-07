import type { CompositionEventHandler, ForwardedRef, RefObject } from 'react';
import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from 'react';

import { InteractionManager } from 'react-native';
import {
  Group,
  Input as TMInput,
  getFontSize,
  useProps,
  useThemeName,
} from 'tamagui';

import platformEnv from '@onekeyhq/shared/src/platformEnv';

import { useSelectionColor } from '../../hooks';
import { useScrollToLocation } from '../../layouts/ScrollView';
import { Icon } from '../../primitives';

import { type IInputAddOnProps, InputAddOnItem } from './InputAddOnItem';
import { getSharedInputStyles } from './sharedStyles';

import type { IGroupProps, IKeyOfIcons } from '../../primitives';
import type {
  HostComponent,
  MeasureLayoutOnSuccessCallback,
  MeasureOnSuccessCallback,
  NativeSyntheticEvent,
  TextInput,
  TextInputFocusEventData,
} from 'react-native';
import type { GetProps } from 'tamagui';

type ITMInputProps = GetProps<typeof TMInput>;

export type IInputProps = {
  displayAsMaskWhenEmptyValue?: boolean;
  readonly?: boolean;
  size?: 'small' | 'medium' | 'large';
  leftIconName?: IKeyOfIcons;
  error?: boolean;
  leftAddOnProps?: IInputAddOnProps;
  addOns?: IInputAddOnProps[];
  allowClear?: boolean; // add clear button when controlled value is not empty
  containerProps?: IGroupProps;
  // not support on Native
  // https://github.com/facebook/react-native/pull/45425
  // About to add to React-Native.
  //
  // https://github.com/Expensify/App/pull/47203/files#diff-9bdb475c2552cf81e4b3cdf2496ef5f779fd501613ac89c1252538b008722abc
  onPaste?: () => void;
  onChangeText?: ((text: string) => string | void) | undefined;
} & Omit<ITMInputProps, 'size' | 'onChangeText'> & {
    /** Web only */
    onCompositionStart?: CompositionEventHandler<any>;
    /** Web only */
    onCompositionEnd?: CompositionEventHandler<any>;
  };

export type IInputRef = {
  focus: () => void;
};

const SIZE_MAPPINGS = {
  'large': {
    paddingLeftWithIcon: '$10',
    height: 44,
    iconLeftPosition: 13,
  },
  'medium': {
    paddingLeftWithIcon: '$9',
    height: 36,
    iconLeftPosition: 9,
  },
  'small': {
    paddingLeftWithIcon: '$8',
    height: 28,
    iconLeftPosition: 5,
  },
};

const useReadOnlyStyle = (readOnly = false) =>
  useMemo(
    () =>
      readOnly
        ? {
            editable: platformEnv.isNativeAndroid ? false : undefined,
            pointerEvents: 'none',
          }
        : undefined,
    [readOnly],
  );

const useAutoFocus = (inputRef: RefObject<TextInput>, autoFocus?: boolean) => {
  const shouldReloadAutoFocus = useMemo(
    () => platformEnv.isRuntimeBrowser && autoFocus,
    [autoFocus],
  );
  useEffect(() => {
    // focus after the animation of Dialog and other containers is finished,
    //  to avoid the misalignment caused by the container recalculating its height
    if (!shouldReloadAutoFocus) {
      return;
    }
    if (platformEnv.isRuntimeChrome) {
      // @ts-expect-error
      inputRef.current?.focus({ preventScroll: true });
    } else {
      setTimeout(() => {
        inputRef.current?.focus();
      }, 150);
    }
  }, [inputRef, shouldReloadAutoFocus]);
  return shouldReloadAutoFocus ? false : autoFocus;
};

function BaseInput(
  inputProps: IInputProps,
  forwardedRef: ForwardedRef<IInputRef>,
) {
  const {
    size = 'medium',
    leftAddOnProps,
    leftIconName,
    addOns: addOnsInProps,
    allowClear,
    disabled,
    editable,
    error,
    containerProps,
    readonly,
    autoFocus,
    selectTextOnFocus,
    onFocus,
    value,
    displayAsMaskWhenEmptyValue,
    onPaste,
    onChangeText,
    keyboardType,
    ...props
  } = useProps(inputProps);
  const { paddingLeftWithIcon, height, iconLeftPosition } = SIZE_MAPPINGS[size];

  const sharedStyles = getSharedInputStyles({
    disabled,
    editable,
    error,
    size,
  });
  const themeName = useThemeName();
  const inputRef: RefObject<TextInput> | null = useRef(null);
  const reloadAutoFocus = useAutoFocus(inputRef, autoFocus);
  const readOnlyStyle = useReadOnlyStyle(readonly);

  const addOns = useMemo<IInputAddOnProps[] | undefined>(() => {
    if (allowClear && inputProps?.value) {
      return [
        ...(addOnsInProps ?? []),
        {
          iconName: 'XCircleOutline',
          onPress: () => {
            inputRef?.current?.clear();
            onChangeText?.('');
          },
        },
      ];
    }
    return addOnsInProps;
  }, [allowClear, inputProps?.value, addOnsInProps, onChangeText]);

  useEffect(() => {
    if (!platformEnv.isNative && inputRef.current && onPaste) {
      const inputElement = inputRef.current as unknown as HTMLInputElement;
      inputElement.addEventListener('paste', onPaste);
      return () => {
        inputElement.removeEventListener('paste', onPaste);
      };
    }
  }, [onPaste]);

  useImperativeHandle(forwardedRef, () => ({
    ...inputRef.current,
    focus: () => {
      inputRef.current?.focus();
    },
    measureLayout: (
      relativeToNativeComponentRef:
        | React.ElementRef<HostComponent<unknown>>
        | number,
      onSuccess: MeasureLayoutOnSuccessCallback,
      onFail?: () => void,
    ) =>
      inputRef.current?.measureLayout(
        relativeToNativeComponentRef,
        onSuccess,
        onFail,
      ),
    measure: (callback: MeasureOnSuccessCallback) =>
      inputRef.current?.measure(callback),
  }));

  const selectionColor = useSelectionColor();

  const valueRef = useRef(value);
  if (valueRef.current !== value) {
    valueRef.current = value;
  }

  const { scrollToView } = useScrollToLocation(inputRef);
  // workaround for selectTextOnFocus={true} not working on Native App
  const handleFocus = useCallback(
    async (e: NativeSyntheticEvent<TextInputFocusEventData>) => {
      onFocus?.(e);
      if (platformEnv.isNative && selectTextOnFocus) {
        const { currentTarget } = e;
        await InteractionManager.runAfterInteractions(() => {
          currentTarget.setNativeProps({
            selection: { start: 0, end: valueRef.current?.length || 0 },
          });
        });
      }
      scrollToView();
    },
    [onFocus, selectTextOnFocus, scrollToView],
  );

  const onNumberPadChangeText = useCallback(
    (text: string) => {
      onChangeText?.(text.replace(',', '.'));
    },
    [onChangeText],
  );

  return (
    <Group
      orientation="horizontal"
      borderWidth={sharedStyles.borderWidth}
      borderColor={sharedStyles.borderColor}
      bg={sharedStyles.backgroundColor}
      borderRadius={sharedStyles.borderRadius}
      disabled={disabled}
      borderCurve="continuous"
      {...containerProps}
    >
      {/* left addon */}
      {leftAddOnProps ? (
        <Group.Item>
          <InputAddOnItem
            {...leftAddOnProps}
            size={size}
            error={error}
            loading={leftAddOnProps.loading}
            label={leftAddOnProps.label}
            iconName={leftAddOnProps.iconName}
            iconColor={leftAddOnProps.iconColor}
            onPress={leftAddOnProps.onPress}
            testID={leftAddOnProps.testID}
          />
        </Group.Item>
      ) : null}

      {/* input */}
      <Group.Item>
        <TMInput
          unstyled
          ref={inputRef}
          keyboardType={keyboardType}
          flex={1}
          // @ts-expect-error
          pointerEvents={readonly ? 'none' : 'auto'}
          /* 
          use height instead of lineHeight because of a RN issue while render TextInput on iOS
          https://github.com/facebook/react-native/issues/28012
        */
          h={height}
          py={sharedStyles.py}
          pr={sharedStyles.px}
          pl={leftIconName ? paddingLeftWithIcon : sharedStyles.px}
          fontSize={
            size === 'small' ? getFontSize('$bodyMd') : getFontSize('$bodyLg')
          }
          color={sharedStyles.color}
          placeholderTextColor={sharedStyles.placeholderTextColor}
          selectionColor={selectionColor}
          cursor={sharedStyles.cursor}
          keyboardAppearance={/dark/.test(themeName) ? 'dark' : 'light'}
          borderCurve="continuous"
          autoFocus={reloadAutoFocus}
          value={
            displayAsMaskWhenEmptyValue && !value
              ? '••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••'
              : value
          }
          onFocus={handleFocus}
          selectTextOnFocus={selectTextOnFocus}
          editable={editable}
          {...readOnlyStyle}
          {...props}
          onChangeText={
            platformEnv.isNativeIOS && keyboardType === 'decimal-pad'
              ? onNumberPadChangeText
              : onChangeText
          }
        />
      </Group.Item>

      {/* left icon */}
      {leftIconName ? (
        <Icon
          position="absolute"
          name={leftIconName}
          size="$5"
          top="50%"
          y="$-2.5"
          left={iconLeftPosition}
          color={disabled ? '$iconDisabled' : '$iconSubdued'}
          pointerEvents="none"
        />
      ) : null}

      {/* right elements */}
      {addOns?.length ? (
        <Group.Item>
          <Group
            borderRadius={sharedStyles.borderRadius}
            orientation="horizontal"
            disabled={disabled}
            disablePassBorderRadius="start"
          >
            {addOns.map(
              (
                {
                  iconName,
                  iconColor,
                  label,
                  onPress,
                  loading,
                  testID = '',
                  renderContent,
                },
                index,
              ) => {
                const getIconColor = () => {
                  if (disabled) {
                    return '$iconDisabled';
                  }
                  if (iconColor) {
                    return iconColor;
                  }
                  return '$iconSubdued';
                };

                return (
                  <Group.Item key={`${iconName || index}-${label || index}`}>
                    {renderContent ?? (
                      <InputAddOnItem
                        testID={testID}
                        key={`${iconName || ''}-${label || ''}`}
                        label={label}
                        loading={loading}
                        size={size}
                        iconName={iconName}
                        iconColor={getIconColor()}
                        error={error}
                        onPress={onPress}
                      />
                    )}
                  </Group.Item>
                );
              },
            )}
          </Group>
        </Group.Item>
      ) : null}
    </Group>
  );
}

const forwardRefInput = forwardRef<IInputRef, IInputProps>(BaseInput);

export const Input = forwardRefInput;

function BaseInputUnControlled(
  inputProps: IInputProps,
  ref: ForwardedRef<IInputRef>,
) {
  const inputRef: RefObject<IInputRef> = useRef(null);

  const [internalValue, setInternalValue] = useState(
    inputProps?.defaultValue || '',
  );
  const handleChange = useCallback(
    (text: string) => {
      setInternalValue(text);
      inputProps?.onChangeText?.(text);
    },
    [inputProps],
  );
  useImperativeHandle(
    ref,
    () =>
      inputRef.current || {
        focus: () => {},
      },
  );
  return (
    <Input
      ref={inputRef}
      {...inputProps}
      value={internalValue}
      onChangeText={handleChange}
    />
  );
}

const forwardRefInputUnControlled = forwardRef<IInputRef, IInputProps>(
  BaseInputUnControlled,
);

export const InputUnControlled = forwardRefInputUnControlled;
