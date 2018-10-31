/**
 * Created by 'Carlos Dávila-Cordero' on 4/25/18.
 */

import {Container} from 'flux/utils';

import App from '../views/App';

import AppStore from '../stores/AppStore';
import AppActions from '../actions/AppActions';

function getStores() {
    return [
        AppStore
    ];
}

function getState() {
    return {
        // ==================== State ====================
        // ------- App --------
        appState: AppStore.getState(),

        // =================== Actions ===================
        setLoginConfig: AppActions.setLoginConfig
    };
}

export default Container.createFunctional(App, getStores, getState);