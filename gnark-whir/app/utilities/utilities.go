package utilities

import (
	"fmt"
	"math/big"
	"reilabs/whir-verifier-circuit/app/typeConverters"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"

	gnark_nimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

func MultivarPoly(coefs []frontend.Variable, vars []frontend.Variable, api frontend.API) frontend.Variable {
	if len(vars) == 0 {
		return coefs[0]
	}
	deg_zero := MultivarPoly(coefs[:len(coefs)/2], vars[:len(vars)-1], api)
	deg_one := api.Mul(vars[len(vars)-1], MultivarPoly(coefs[len(coefs)/2:], vars[:len(vars)-1], api))
	return api.Add(deg_zero, deg_one)
}

func UnivarPoly(api frontend.API, coefficients []frontend.Variable, points []frontend.Variable) []frontend.Variable {
	results := make([]frontend.Variable, len(points))
	for j := range points {
		ans := frontend.Variable(0)
		for i := range coefficients {
			ans = api.Add(api.Mul(ans, points[j]), coefficients[len(coefficients)-1-i])
		}
		results[j] = ans
	}
	return results
}

func IndexOf(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(outputs) != 1 {
		return fmt.Errorf("expecting one output")
	}

	if len(inputs) == 0 {
		return fmt.Errorf("inputs array cannot be empty")
	}

	target := inputs[0]

	for i := 1; i < len(inputs); i++ {
		if inputs[i].Cmp(target) == 0 {
			outputs[0] = big.NewInt(int64(i - 1))
			return nil
		}
	}

	outputs[0] = big.NewInt(-1)
	return nil
}

func Reverse[T any](s []T) []T {
	res := make([]T, len(s))
	copy(res, s)
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		res[i], res[j] = s[j], s[i]
	}
	return res
}

func PrefixDecodePath[T any](prevPath []T, prefixLen uint64, suffix []T) []T {
	if prefixLen == 0 {
		res := make([]T, len(suffix))
		copy(res, suffix)
		return res
	} else {
		res := make([]T, prefixLen+uint64(len(suffix)))
		copy(res, prevPath[:prefixLen])
		copy(res[prefixLen:], suffix)
		return res
	}
}

func PoW(api frontend.API, sc *skyscraper.Skyscraper, arthur gnark_nimue.Arthur, difficulty int) ([]uints.U8, []uints.U8, error) {
	challenge := make([]uints.U8, 32)
	if err := arthur.FillChallengeBytes(challenge); err != nil {
		return nil, nil, err
	}
	// api.Println(challenge)
	nonce := make([]uints.U8, 8)

	if err := arthur.FillNextBytes(nonce); err != nil {
		return nil, nil, err
	}
	// api.Println(nonce)
	challengeFieldElement := typeConverters.LittleEndianFromUints(api, challenge)
	nonceFieldElement := typeConverters.BigEndianFromUints(api, nonce)
	// api.Println(nonceFieldElement)
	err := CheckPoW(api, sc, challengeFieldElement, nonceFieldElement, difficulty)
	if err != nil {
		return nil, nil, err
	}
	return challenge, nonce, nil
}

func CheckPoW(api frontend.API, sc *skyscraper.Skyscraper, challenge frontend.Variable, nonce frontend.Variable, difficulty int) error {
	hash := sc.CompressV2(challenge, nonce)

	d0, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	d1, _ := new(big.Int).SetString("10944121435919637611123202872628637544274182200208017171849102093287904247808", 10)
	d2, _ := new(big.Int).SetString("5472060717959818805561601436314318772137091100104008585924551046643952123904", 10)
	d3, _ := new(big.Int).SetString("2736030358979909402780800718157159386068545550052004292962275523321976061952", 10)
	d4, _ := new(big.Int).SetString("1368015179489954701390400359078579693034272775026002146481137761660988030976", 10)
	d5, _ := new(big.Int).SetString("684007589744977350695200179539289846517136387513001073240568880830494015488", 10)
	d6, _ := new(big.Int).SetString("342003794872488675347600089769644923258568193756500536620284440415247007744", 10)
	d7, _ := new(big.Int).SetString("171001897436244337673800044884822461629284096878250268310142220207623503872", 10)
	d8, _ := new(big.Int).SetString("85500948718122168836900022442411230814642048439125134155071110103811751936", 10)
	d9, _ := new(big.Int).SetString("42750474359061084418450011221205615407321024219562567077535555051905875968", 10)
	d10, _ := new(big.Int).SetString("21375237179530542209225005610602807703660512109781283538767777525952937984", 10)
	d11, _ := new(big.Int).SetString("10687618589765271104612502805301403851830256054890641769383888762976468992", 10)
	d12, _ := new(big.Int).SetString("5343809294882635552306251402650701925915128027445320884691944381488234496", 10)
	d13, _ := new(big.Int).SetString("2671904647441317776153125701325350962957564013722660442345972190744117248", 10)
	d14, _ := new(big.Int).SetString("1335952323720658888076562850662675481478782006861330221172986095372058624", 10)
	d15, _ := new(big.Int).SetString("667976161860329444038281425331337740739391003430665110586493047686029312", 10)
	d16, _ := new(big.Int).SetString("333988080930164722019140712665668870369695501715332555293246523843014656", 10)
	d17, _ := new(big.Int).SetString("166994040465082361009570356332834435184847750857666277646623261921507328", 10)
	d18, _ := new(big.Int).SetString("83497020232541180504785178166417217592423875428833138823311630960753664", 10)
	d19, _ := new(big.Int).SetString("41748510116270590252392589083208608796211937714416569411655815480376832", 10)
	d20, _ := new(big.Int).SetString("20874255058135295126196294541604304398105968857208284705827907740188416", 10)
	d21, _ := new(big.Int).SetString("10437127529067647563098147270802152199052984428604142352913953870094208", 10)
	d22, _ := new(big.Int).SetString("5218563764533823781549073635401076099526492214302071176456976935047104", 10)
	d23, _ := new(big.Int).SetString("2609281882266911890774536817700538049763246107151035588228488467523552", 10)
	d24, _ := new(big.Int).SetString("1304640941133455945387268408850269024881623053575517794114244233761776", 10)
	d25, _ := new(big.Int).SetString("652320470566727972693634204425134512440811526787758897057122116880888", 10)
	d26, _ := new(big.Int).SetString("326160235283363986346817102212567256220405763393879448528561058440444", 10)
	d27, _ := new(big.Int).SetString("163080117641681993173408551106283628110202881696939724264280529220222", 10)

	var arr = [28]*big.Int{d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27}
	api.AssertIsLessOrEqual(hash, arr[difficulty])
	return nil
}

func EqPolyOutside(api frontend.API, coords []frontend.Variable, point []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(1)
	for i := range coords {
		acc = api.Mul(acc, api.Add(api.Mul(coords[i], point[i]), api.Mul(api.Sub(frontend.Variable(1), coords[i]), api.Sub(frontend.Variable(1), point[i]))))
	}
	return acc
}

func EvaluateQuadraticPolynomialFromEvaluationList(api frontend.API, evaluations []frontend.Variable, point frontend.Variable) (ans frontend.Variable) {
	inv2 := api.Inverse(2)
	b0 := evaluations[0]
	b1 := api.Mul(api.Add(api.Neg(evaluations[2]), api.Mul(4, evaluations[1]), api.Mul(-3, evaluations[0])), inv2)
	b2 := api.Mul(api.Add(evaluations[2], api.Mul(-2, evaluations[1]), evaluations[0]), inv2)
	return api.Add(api.Mul(point, point, b2), api.Mul(point, b1), b0)
}

func Exponent(api frontend.API, uapi *uints.BinaryField[uints.U64], X frontend.Variable, Y uints.U64) frontend.Variable {
	output := frontend.Variable(1)
	bits := api.ToBinary(uapi.ToValue(Y))
	multiply := frontend.Variable(X)
	for i := range bits {
		output = api.Select(bits[i], api.Mul(output, multiply), output)
		multiply = api.Mul(multiply, multiply)
	}
	return output
}

func CheckSumOverBool(api frontend.API, value frontend.Variable, polyEvals []frontend.Variable) {
	sumOverBools := api.Add(polyEvals[0], polyEvals[1])
	api.AssertIsEqual(value, sumOverBools)
}

func ExpandRandomness(api frontend.API, base frontend.Variable, len int) []frontend.Variable {
	res := make([]frontend.Variable, len)
	acc := frontend.Variable(1)
	for i := range len {
		res[i] = acc
		acc = api.Mul(acc, base)
	}
	return res
}

func ExpandFromUnivariate(api frontend.API, base frontend.Variable, len int) []frontend.Variable {
	res := make([]frontend.Variable, len)
	acc := base
	for i := range len {
		res[len-1-i] = acc
		acc = api.Mul(acc, acc)
	}
	return res
}

func IsSubset(api frontend.API, uapi *uints.BinaryField[uints.U64], arthur gnark_nimue.Arthur, indexes []frontend.Variable, merkleIndexes []uints.U64) error {
	dedupedLUT := logderivlookup.New(api)
	inputArr := make([]frontend.Variable, len(merkleIndexes)+1)

	for j, index := range merkleIndexes {
		dedupedLUT.Insert(uapi.ToValue(index))
		inputArr[1+j] = uapi.ToValue(index)
	}

	for _, x := range indexes {
		inputArr[0] = x
		res, newerr := api.Compiler().NewHint(IndexOf, 1, inputArr...)
		if newerr != nil {
			return newerr
		}
		searchRes := dedupedLUT.Lookup(res[0])
		//api.Println(searchRes...)
		api.AssertIsEqual(x, searchRes[0])
	}
	return nil
}

func DotProduct(api frontend.API, a []frontend.Variable, b []frontend.Variable) frontend.Variable {
	var acc = frontend.Variable(0)
	for i := range a {
		acc = api.Add(acc, api.Mul(a[i], b[i]))
	}
	return acc
}
