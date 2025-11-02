// package mock contains the generated mocks for the project.
package mock

//go:generate mockgen -package access -source ../access_iface.go -destination ../mock_access_iface.go
//go:generate mockgen -package access -source ../store/store_iface.go -destination ../mock_store_iface.go
//go:generate mockgen -package access -source ../usermanagemant_iface.go -destination ../mock_usermanagemant_iface.go
