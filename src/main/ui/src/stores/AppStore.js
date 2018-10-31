/**
 * Created by 'Carlos Dávila-Cordero' on 4/25/18.
 */

import {ReduceStore} from 'flux/utils';
import AppDispatcher from '../AppDispatcher';
import AppActionTypes from '../actions/AppActionTypes';

const stateCallbacks = (function () {
    function setLoginConfig(state, action) {
        return Object.assign({}, state, {loginConfig: action.config});
    }

    return {
        [Symbol.for(AppActionTypes.SET_LOGIN_CONFIG)]: setLoginConfig
    }
}());

const AppStore = class extends ReduceStore {
    constructor() {
        super(AppDispatcher);
        this.getInitialState = this.getInitialState.bind(this);
    }

    getInitialState() {
        return {
            loginConfig: undefined
        };
    }

    reduce(state, action) {
        if (stateCallbacks[Symbol.for(action.type)]) {
            return stateCallbacks[Symbol.for(action.type)](state, action);
        }
        else {
            return state;
        }
    }
};

export default new AppStore();