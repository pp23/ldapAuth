package provider

/* A provider can be used in configuration where data needs to be read from specific sources
*  A provider reads data from files and defines a configuration to define the required config
*  paramaters to provide the data.
 */
type Provider interface {
	Open() error
	Read() ([]byte, error)
	Close() error
}
