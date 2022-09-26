from project import app
import configparser
from project import readConfig


if __name__ == '__main__':
    readConfig()
    app.run(debug=True)