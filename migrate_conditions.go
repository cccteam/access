package access

import (
	"time"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/accesstypes/condition"
	"github.com/go-playground/errors/v5"
)

// This file validates a grant's condition at deploy time, against the
// application Collection's vocabulary: the condition must parse, reference
// only attributes the resource declares and subject vocabulary the
// application declares, use the post-image only where a mutation proposes
// values, and compare literals of the attribute's comparison type. Everything
// caught here would otherwise surface as a per-request check or rendering
// error — deploy is the last moment the mistake is the operator's alone.

// validateGrantCondition checks one authored grant's condition text.
func validateGrantCondition(store PermissionCollection, role accesstypes.Role, perm accesstypes.Permission, grant Grant) error {
	fail := func(err error) error {
		return errors.Wrapf(err, "role %s: %s grant on %s", role, perm, grant.Resource)
	}

	compiled, err := accesstypes.NewCondition(grant.Condition)
	if err != nil {
		return fail(err)
	}
	expr := compiled.Expr()

	// Execute permissions check at decode time, where no row exists: only a
	// row-free condition — one that folds against the environment facts alone —
	// can ever settle there (design plan §12, revised 2026-08-31).
	if perm == accesstypes.Execute && (!condition.RowFree(expr) || len(condition.SubjectValues(expr)) > 0) {
		return fail(errors.New("execute permissions check at decode time, where no row exists: only row-free conditions (environment facts) are permitted"))
	}

	scope := store.Scope(grant.Resource)

	for _, name := range condition.Bindings(expr) {
		if _, ok := store.AttributeComparisonType(scope, grant.Resource, name); !ok {
			return fail(errors.Newf("condition references %q, which is not an attribute of %s", name, grant.Resource))
		}
	}
	for _, name := range condition.SubjectSets(expr) {
		if !store.DeclaresSubjectSet(name) {
			return fail(errors.Newf("condition references subject.%s, which is not a declared subject set", name))
		}
	}
	for _, name := range condition.SubjectValues(expr) {
		if !store.DeclaresSubjectValue(name) {
			return fail(errors.Newf("condition references subject.%s, which is not a declared subject value", name))
		}
	}

	if condition.UsesPostImage(expr) {
		if perm != accesstypes.Create && perm != accesstypes.Update {
			return fail(errors.Newf("condition reads the post-image (new.), which only create and update mutations propose"))
		}
	}

	if err := validateConditionTypes(store, scope, grant.Resource, expr); err != nil {
		return fail(err)
	}

	return nil
}

// validateConditionTypes walks the expression's leaves and validates each
// against the referenced attribute's comparison type. The database stays the
// one comparison engine — this rejects only conditions that could never hold
// or would compare across types.
func validateConditionTypes(store PermissionCollection, scope accesstypes.PermissionScope, res accesstypes.Resource, expr condition.Expr) error {
	switch n := expr.(type) {
	case condition.And:
		for _, operand := range n.Operands {
			if err := validateConditionTypes(store, scope, res, operand); err != nil {
				return err
			}
		}
	case condition.Or:
		for _, operand := range n.Operands {
			if err := validateConditionTypes(store, scope, res, operand); err != nil {
				return err
			}
		}
	case condition.Not:
		return validateConditionTypes(store, scope, res, n.Operand)
	case condition.Comparison:
		return validateComparisonTypes(store, scope, res, n)
	case condition.In:
		return validateInTypes(store, scope, res, n)
	case condition.NullTest, condition.Truth:
		// Nothing to type: IS NULL tests presence, and Truth is a folded fact.
	}

	return nil
}

func validateComparisonTypes(store PermissionCollection, scope accesstypes.PermissionScope, res accesstypes.Resource, cmp condition.Comparison) error {
	if cmp.Left.IsNow() {
		// now compares against timestamp strings (or, degenerately, itself as
		// an attribute comparison's operand — handled below).
		if literal, ok := cmp.Right.(condition.StringLiteral); ok {
			return validateLiteralType(accesstypes.AttributeTypeTimestamp, "now", condition.Literal(literal))
		}

		return nil
	}

	attrType, err := refType(store, scope, res, cmp.Left)
	if err != nil {
		return err
	}

	switch operand := cmp.Right.(type) {
	case condition.StringLiteral:
		return validateLiteralType(attrType, cmp.Left.Name, operand)
	case condition.NumberLiteral:
		return validateLiteralType(attrType, cmp.Left.Name, operand)
	case condition.BoolLiteral:
		return validateLiteralType(attrType, cmp.Left.Name, operand)
	case condition.Subject:
		if attrType != accesstypes.AttributeTypeString {
			return errors.Newf("%s is a %s attribute and cannot compare against subject, a user id", cmp.Left.Name, attrType)
		}
	case condition.Now:
		if attrType != accesstypes.AttributeTypeTimestamp {
			return errors.Newf("%s is a %s attribute and cannot compare against now, a timestamp", cmp.Left.Name, attrType)
		}
	case condition.SubjectValue:
		// The subject value's column type is the anchor table's business; the
		// database compares.
	}

	return nil
}

func validateInTypes(store PermissionCollection, scope accesstypes.PermissionScope, res accesstypes.Resource, in condition.In) error {
	if in.SubjectSet != "" {
		return nil
	}

	attrType, err := refType(store, scope, res, in.Left)
	if err != nil {
		return err
	}
	for _, literal := range in.Literals {
		if err := validateLiteralType(attrType, in.Left.Name, literal); err != nil {
			return err
		}
	}

	return nil
}

func refType(store PermissionCollection, scope accesstypes.PermissionScope, res accesstypes.Resource, ref condition.Ref) (accesstypes.AttributeType, error) {
	attrType, ok := store.AttributeComparisonType(scope, res, ref.Name)
	if !ok {
		return "", errors.Newf("condition references %q, which is not an attribute of %s", ref.Name, res)
	}
	if ref.PostImage && !store.AttributeIsColumn(scope, res, ref.Name) {
		return "", errors.Newf("new.%s reads a join-path attribute, which has no proposed value", ref.Name)
	}

	return attrType, nil
}

// validateLiteralType checks one literal against the attribute's comparison
// type: numbers to number attributes, booleans to bool, strings to string —
// and to timestamp or date attributes when the string parses as the pinned
// format (RFC 3339, or YYYY-MM-DD).
func validateLiteralType(attrType accesstypes.AttributeType, name string, literal condition.Literal) error {
	switch l := literal.(type) {
	case condition.StringLiteral:
		switch attrType {
		case accesstypes.AttributeTypeString:
			return nil
		case accesstypes.AttributeTypeTimestamp:
			if _, err := time.Parse(time.RFC3339, l.Value); err != nil {
				return errors.Newf("%s is a timestamp attribute; %q is not an RFC 3339 timestamp", name, l.Value)
			}

			return nil
		case accesstypes.AttributeTypeDate:
			if _, err := time.Parse(time.DateOnly, l.Value); err != nil {
				return errors.Newf("%s is a date attribute; %q is not a YYYY-MM-DD date", name, l.Value)
			}

			return nil
		case accesstypes.AttributeTypeNumber, accesstypes.AttributeTypeBool:
			return errors.Newf("%s is a %s attribute and cannot compare against the string %q", name, attrType, l.Value)
		}
	case condition.NumberLiteral:
		if attrType != accesstypes.AttributeTypeNumber {
			return errors.Newf("%s is a %s attribute and cannot compare against the number %s", name, attrType, l.Text)
		}

		return nil
	case condition.BoolLiteral:
		if attrType != accesstypes.AttributeTypeBool {
			return errors.Newf("%s is a %s attribute and cannot compare against a boolean", name, attrType)
		}

		return nil
	}

	return nil
}
