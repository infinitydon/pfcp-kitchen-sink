// Code generated by "enumer -type=ApplyAction -yaml"; DO NOT EDIT.

//
package pfcp

import (
	"fmt"
)

const (
	_ApplyActionName_0 = "DropForward"
	_ApplyActionName_1 = "Buffer"
	_ApplyActionName_2 = "NotifyCP"
	_ApplyActionName_3 = "Duplicate"
)

var (
	_ApplyActionIndex_0 = [...]uint8{0, 4, 11}
	_ApplyActionIndex_1 = [...]uint8{0, 6}
	_ApplyActionIndex_2 = [...]uint8{0, 8}
	_ApplyActionIndex_3 = [...]uint8{0, 9}
)

func (i ApplyAction) String() string {
	switch {
	case 1 <= i && i <= 2:
		i -= 1
		return _ApplyActionName_0[_ApplyActionIndex_0[i]:_ApplyActionIndex_0[i+1]]
	case i == 4:
		return _ApplyActionName_1
	case i == 8:
		return _ApplyActionName_2
	case i == 16:
		return _ApplyActionName_3
	default:
		return fmt.Sprintf("ApplyAction(%d)", i)
	}
}

var _ApplyActionValues = []ApplyAction{1, 2, 4, 8, 16}

var _ApplyActionNameToValueMap = map[string]ApplyAction{
	_ApplyActionName_0[0:4]:  1,
	_ApplyActionName_0[4:11]: 2,
	_ApplyActionName_1[0:6]:  4,
	_ApplyActionName_2[0:8]:  8,
	_ApplyActionName_3[0:9]:  16,
}

// ApplyActionString retrieves an enum value from the enum constants string name.
// Throws an error if the param is not part of the enum.
func ApplyActionString(s string) (ApplyAction, error) {
	if val, ok := _ApplyActionNameToValueMap[s]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("%s does not belong to ApplyAction values", s)
}

// ApplyActionValues returns all values of the enum
func ApplyActionValues() []ApplyAction {
	return _ApplyActionValues
}

// IsAApplyAction returns "true" if the value is listed in the enum definition. "false" otherwise
func (i ApplyAction) IsAApplyAction() bool {
	for _, v := range _ApplyActionValues {
		if i == v {
			return true
		}
	}
	return false
}

// MarshalYAML implements a YAML Marshaler for ApplyAction
func (i ApplyAction) MarshalYAML() (interface{}, error) {
	return i.String(), nil
}

// UnmarshalYAML implements a YAML Unmarshaler for ApplyAction
func (i *ApplyAction) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	var err error
	*i, err = ApplyActionString(s)
	return err
}
