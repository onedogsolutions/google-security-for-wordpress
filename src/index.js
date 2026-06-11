import { render } from '@wordpress/element';
import App from './components/App';
import './styles/index.css';

const rootElement = document.getElementById( 'recaptcha-woo-admin-root' );
if ( rootElement ) {
	render( <App />, rootElement );
}
