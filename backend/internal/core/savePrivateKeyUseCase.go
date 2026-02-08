package core

type SavePrivateKeyUseCase struct {
	keys IPrivateKeys
}

type PrivateKey struct {
	Value string
	Name string
}

func (uc *SavePrivateKeyUseCase) Execute(value string, name string) error {
	key := PrivateKey{
		Value: value,
		Name: name,
	}

	return uc.keys.SavePrivateKey(&key)
}
