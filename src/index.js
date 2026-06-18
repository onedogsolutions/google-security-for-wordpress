import { render } from '@wordpress/element';
import App from './components/App';
import './styles/index.css';

const rootElement = document.getElementById( 'gswp-admin-root' );
if ( rootElement ) {
	render( <App />, rootElement );
}
