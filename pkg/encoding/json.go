package encoding

import "encoding/json"

// StructToJsonBytes converts a struct to JSON bytes
func StructToJsonBytes(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// JsonBytesToStruct converts JSON bytes to a struct
func JsonBytesToStruct(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
