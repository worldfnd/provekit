package polynomial

import "github.com/consensys/gnark/frontend"

// Multivar evaluates a multivariate polynomial with coefficients laid out in
// lexicographic order against the provided variables.
func Multivar(api frontend.API, coefficients []frontend.Variable, variables []frontend.Variable) frontend.Variable {
	if len(variables) == 0 {
		if len(coefficients) == 0 {
			return frontend.Variable(0)
		}
		return coefficients[0]
	}

	mid := len(coefficients) / 2
	degreeZero := Multivar(api, coefficients[:mid], variables[:len(variables)-1])
	degreeOne := api.Mul(
		variables[len(variables)-1],
		Multivar(api, coefficients[mid:], variables[:len(variables)-1]),
	)
	return api.Add(degreeZero, degreeOne)
}

// Univar evaluates a univariate polynomial (coefficients in increasing degree
// order) over a slice of points.
func Univar(api frontend.API, coefficients []frontend.Variable, points []frontend.Variable) []frontend.Variable {
	if len(points) == 0 {
		return coefficients
	}

	results := make([]frontend.Variable, len(points))
	for j := range points {
		acc := frontend.Variable(0)
		for i := range coefficients {
			acc = api.Add(
				api.Mul(acc, points[j]),
				coefficients[len(coefficients)-1-i],
			)
		}
		results[j] = acc
	}
	return results
}

// EqualityOutside returns the equality polynomial evaluated outside the Boolean
// hypercube for the supplied coordinates and target point.
func EqualityOutside(api frontend.API, coords []frontend.Variable, point []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(1)
	for i := range coords {
		acc = api.Mul(
			acc,
			api.Add(
				api.Mul(coords[i], point[i]),
				api.Mul(api.Sub(frontend.Variable(1), coords[i]), api.Sub(frontend.Variable(1), point[i])),
			),
		)
	}
	return acc
}

// EvaluateQuadraticFromEvaluations interpolates a quadratic polynomial from its
// evaluations at 0, 1, and 2 and then evaluates it at the supplied point.
func EvaluateQuadraticFromEvaluations(api frontend.API, evaluations []frontend.Variable, point frontend.Variable) frontend.Variable {
	inv2 := api.Inverse(2)
	b0 := evaluations[0]
	b1 := api.Mul(
		api.Add(
			api.Neg(evaluations[2]),
			api.Mul(4, evaluations[1]),
			api.Mul(-3, evaluations[0]),
		),
		inv2,
	)
	b2 := api.Mul(
		api.Add(
			evaluations[2],
			api.Mul(-2, evaluations[1]),
			evaluations[0],
		),
		inv2,
	)
	return api.Add(
		api.Mul(point, point, b2),
		api.Mul(point, b1),
		b0,
	)
}

// ExpandRandomness expands the supplied base to the requested length by
// accumulating multiplicative powers.
func ExpandRandomness(api frontend.API, base frontend.Variable, length int) []frontend.Variable {
	res := make([]frontend.Variable, length)
	acc := frontend.Variable(1)
	for i := 0; i < length; i++ {
		res[i] = acc
		acc = api.Mul(acc, base)
	}
	return res
}

// ExpandFromUnivariate expands the supplied base element into a power ladder
// suitable for equality polynomial checks.
func ExpandFromUnivariate(api frontend.API, base frontend.Variable, length int) []frontend.Variable {
	res := make([]frontend.Variable, length)
	acc := base
	for i := 0; i < length; i++ {
		res[length-1-i] = acc
		acc = api.Mul(acc, acc)
	}
	return res
}

// DotProduct computes the dot product of two equal-length slices inside the
// circuit.
func DotProduct(api frontend.API, a []frontend.Variable, b []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	for i := range a {
		acc = api.Add(acc, api.Mul(a[i], b[i]))
	}
	return acc
}
