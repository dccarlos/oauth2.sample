import React from 'react';
import logo from '../logo.svg';
import "bootstrap/dist/css/bootstrap.css";
import '../App.css';

import {Button} from 'react-bootstrap';

function processResponse(response) {
    var contentType = response.headers.get("content-type");
    if (contentType && contentType.indexOf("application/json") !== -1) {
        return response.json();
    }
    else return {error: response.statusText};
}



class LoginNavBar extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            protected: undefined
        };

        this.onClickTestButton = this.onClickTestButton.bind(this);
    }

    componentWillMount() {
        return fetch('/api/auth/user')
            .then(response => {
                if (response && response.headers) {
                    let accessToken = response.headers.get('access-token');
                    if (accessToken) {
                        this.props.context.setLoginConfig({token: accessToken, success: true});
                    }
                    else {
                        this.props.context.setLoginConfig({success: false});
                    }
                }
                else {
                    this.props.context.setLoginConfig({success: false});
                }
            })
            .catch((error) => {
                console.error(error);
                this.props.context.setLoginConfig({success: false});
            });
    }

    onClickTestButton() {

        let auth = 'Bearer ' + this.props.context.appState.loginConfig.token;

        fetch('/api/v1/admin/protected', {
            method: 'GET',
            headers: {'Content-Type': 'application/json', 'Authorization': auth},
            credentials: 'include'
        }).then(processResponse)
            .then((response) => {
                this.setState({
                    protected: response
                });
            })
            .catch((error) => {
                console.error(error);
            });
    }

    render() {
        let loginLabel = this.props.context.appState.loginConfig
            && this.props.context.appState.loginConfig.success
            ? 'LOGGED IN!'
            : 'NOT LOGGED';

        let loggedUser = this.props.context.appState.loginConfig;

        let obtained = this.state.protected ? JSON.stringify(this.state.protected) : '';

        let widget = (
            <div className="App">
                <header className="App-header">
                    <img src={logo} className="App-logo" alt="logo"/>
                    <p>
                        Edit <code>src/views/App.js</code> and save to reload.
                    </p>
                    <a
                        className="App-link"
                        href="https://reactjs.org"
                        target="_blank"
                        rel="noopener noreferrer">
                        <p>
                            {loginLabel}
                        </p>
                    </a>
                    <div>
                        <Button bsStyle="info" onClick={this.onClickTestButton}>
                            Test button!
                        </Button>
                        <p>
                            {obtained}
                        </p>
                    </div>
                </header>
            </div>
        );

        if (loggedUser) {
            if(loggedUser.success) {
                return widget;
            }
            else {
                window.location.href = '/api/auth/login';
            }
        }
        else {
            return null;
        }
    }
}

export default function AppFunction(props) {
    return (
        <div>
            <LoginNavBar context={props}/>
        </div>
    );
};