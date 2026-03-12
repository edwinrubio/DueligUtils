package testhelpers

import "time"

// NewJugadorPayload returns a registration payload for a unique test jugador.
// suffix is appended to email to allow multiple jugadores in one test run.
func NewJugadorPayload(suffix string) map[string]interface{} {
	return map[string]interface{}{
		"email":    "test-jugador-" + suffix + "@duelig.co",
		"password": "Test1234!",
		"nombre":   "Jugador Test " + suffix,
		"rol":      "Jugador",
	}
}

// NewCDOPayload returns a registration payload for a unique test CDO.
func NewCDOPayload(suffix string) map[string]interface{} {
	return map[string]interface{}{
		"email":    "test-cdo-" + suffix + "@duelig.co",
		"password": "Test1234!",
		"nombre":   "CDO Test " + suffix,
		"rol":      "Dueniocentro",
	}
}

// NewCanchaPayload returns a cancha creation payload with COP centavos pricing.
// precio: price per hour in COP centavos (e.g., 5000000 = $50,000 COP)
func NewCanchaPayload(nombre string, precioCentavos int) map[string]interface{} {
	horario := map[string]interface{}{
		"hora_inicio": "08:00",
		"hora_fin":    "22:00",
		"precio":      precioCentavos,
	}
	return map[string]interface{}{
		"nombre": nombre,
		"precio": map[string]interface{}{
			"lunes":     []interface{}{horario},
			"martes":    []interface{}{horario},
			"miercoles": []interface{}{horario},
			"jueves":    []interface{}{horario},
			"viernes":   []interface{}{horario},
			"sabado":    []interface{}{horario},
			"domingo":   []interface{}{horario},
		},
	}
}

// NextWeekday returns a date string (YYYY-MM-DD) for the next occurrence
// of the given weekday (0=Sunday...6=Saturday) in America/Bogota.
// Use for reservation dates — never hardcode dates.
func NextWeekday(weekday time.Weekday) string {
	loc, _ := time.LoadLocation("America/Bogota")
	now := time.Now().In(loc)
	daysUntil := int(weekday) - int(now.Weekday())
	if daysUntil <= 0 {
		daysUntil += 7
	}
	target := now.AddDate(0, 0, daysUntil)
	return target.Format("2006-01-02")
}
