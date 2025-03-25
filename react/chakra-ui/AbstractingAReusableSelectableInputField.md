[Chakra UI's Select component](https://chakra-ui.com/docs/components/select) is a React component that allows a user to pick from a list
of predefined options. It is extremely configurable but this often leads to a large, complex nested structure for even the simplest task.

Nesting related components within one another in this fashion is known as the **compound component pattern** and is a popular approach for most front-end libraries, with the keyword here being _libraries_. It allows for maximal flexibility at the cost of complexity.

From the application/consumer's perspective, it is often advisable to abstract this complexity away into a facade pattern, exposing only those aspects of the api that are relevant for the business logic of the app.

Consider the example of a simple, selectable field component that's used in a form. Here's how to do it purely using Chakra UI.

#### first the field needs to be wrapped in Field.Root

```js
<Field.Root>...</Field.Root>
```

#### the content inside will be wrapped in Controller, which takes a render prop for defining how the field will be rendered

```js
<Field.Root>
    <Field.Label>...</Field.Label>
    <Controller
        ...
        render={({field}) => (...)}
    />
</Field.Root>
```

#### the field will be wrapped in Select.Root, along with all the other Select subcomponents necessary to get it working

```js
<Field.Root>
    <Field.Label>...</Field.Label>
    <Controller
        ...
        render={({field}) => (
          <Select.Root
            name={field.name}
            onValueChange={({ value }) => field.onChange(value[0])}
            defaultValue={[field.value]}
            collection={collection}
          >
            <Select.HiddenSelect />
            <Select.Control>
              <Select.Trigger>
                <Select.ValueText placeholder={placeholder} />
              </Select.Trigger>
              <Select.IndicatorGroup>
                <Select.Indicator />
              </Select.IndicatorGroup>
            </Select.Control>
            <Select.Positioner>
              <Select.Content>
                {collection.items.map((item) => (
                  <Select.Item item={item} key={item.value}>
                    {item.label}
                    <Select.ItemIndicator />
                  </Select.Item>
                ))}
              </Select.Content>
            </Select.Positioner>
          </Select.Root>
        )}
    />
</Field.Root>
```

Having to perform these steps every single time the app needs a Select field is cumbersome. All of this complexity can easily be abstracted
into a facade pattern that only exposes what's necessary for the app.

```js
function SimpleSelectable({
  label,
  name,
  collection,
  placeholder,
  defaultValue,
  disable,
  control,
}: SimpleSelectableProps) {
  return (
    <Field.Root>
      <Field.Label>{label}</Field.Label>
      <Controller
        control={control}
        name={name}
        defaultValue={defaultValue}
        render={({ field }) => (
          <Select.Root
            name={field.name}
            disabled={disable ?? false}
            onValueChange={({ value }) => field.onChange(value[0])}
            defaultValue={[field.value]}
            collection={collection}
          >
            <Select.HiddenSelect />
            <Select.Control>
              <Select.Trigger>
                <Select.ValueText placeholder={placeholder} />
              </Select.Trigger>
              <Select.IndicatorGroup>
                <Select.Indicator />
              </Select.IndicatorGroup>
            </Select.Control>
            <Select.Positioner>
              <Select.Content>
                {collection.items.map((item) => (
                  <Select.Item item={item} key={item.value}>
                    {item.label}
                    <Select.ItemIndicator />
                  </Select.Item>
                ))}
              </Select.Content>
            </Select.Positioner>
          </Select.Root>
        )}
      />
    </Field.Root>
  );
}
```

Now, whenever a selectable field is required in the app, we invoke the SimpleSelectable component like this:

```js
<SimpleSelectable
  disable={isDisabled}
  label={label}
  name={name}
  defaultValue={default}
  collection={items}
  control={control}
/>
```
