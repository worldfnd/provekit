package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

func calculateEQ(api frontend.API, alphas []frontend.Variable, r []frontend.Variable) frontend.Variable {
	ans := frontend.Variable(1)
	for i, alpha := range alphas {
		ans = api.Mul(ans, api.Add(api.Mul(alpha, r[i]), api.Mul(api.Sub(frontend.Variable(1), alpha), api.Sub(frontend.Variable(1), r[i]))))
	}
	return ans
}

func initializeComponents(api frontend.API, circuit *Circuit) (*skyscraper.Skyscraper, gnarkNimue.Arthur, *uints.BinaryField[uints.U64], error) {
	sc := skyscraper.NewSkyscraper(api, 2)
	arthur, err := gnarkNimue.NewSkyscraperArthur(api, sc, circuit.IO, circuit.Transcript[:], true)
	if err != nil {
		return nil, nil, nil, err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, nil, nil, err
	}
	return sc, arthur, uapi, nil
}
