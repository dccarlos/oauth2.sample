import React from 'react';
import ReactDOM from 'react-dom';

import {BrowserRouter as Router, Route} from 'react-router-dom';

import './index.css';
import * as serviceWorker from './serviceWorker';

import AppContainer from './containers/AppContainer';

ReactDOM.render(
    <Router>
        <Route exact path="/" component={AppContainer}/>
    </Router>,
    document.getElementById('root'));

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister();
