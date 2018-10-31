/**
 * Created by 'Carlos Dávila-Cordero' on 4/25/18.
 */

import AppActionTypes from './AppActionTypes';
import AppDispatcher from '../AppDispatcher';

const AppActions = {


    setLoginConfig(config) {
        AppDispatcher.dispatch({
            type: AppActionTypes.SET_LOGIN_CONFIG,
            config
        });
    }
};

export default AppActions;