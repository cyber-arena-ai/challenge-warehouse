package models

import "encoding/json"

type JsonOwnership struct {
	Ref *Ownership
}

func (jo *JsonOwnership) UnmarshalJSON(data []byte) error {
	var v struct {
		ContentHash []byte `json:"content_hash"`
		Name        string `json:"name"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	jo.Ref.ContentHash = ToHash(v.ContentHash)
	jo.Ref.Name = v.Name
	return nil
}

func (jo JsonOwnership) MarshalJSON() ([]byte, error) {
	var v struct {
		ContentHash []byte `json:"content_hash"`
		Name        string `json:"name"`
	}
	v.ContentHash = jo.Ref.ContentHash[:]
	v.Name = jo.Ref.Name
	return json.Marshal(v)
}
