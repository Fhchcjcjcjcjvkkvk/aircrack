#include <QApplication>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>
#include <QMenuBar>
#include <QAction>
#include <QMessageBox>

class Spreadsheet : public QWidget {
    Q_OBJECT

public:
    Spreadsheet(QWidget *parent = nullptr) : QWidget(parent) {
        // Nastavení rozvržení
        auto *layout = new QVBoxLayout(this);

        // Vytvoření tabulky
        tableWidget = new QTableWidget(10, 5, this); // 10 řádků, 5 sloupců
        tableWidget->setHorizontalHeaderLabels({"A", "B", "C", "D", "E"});
        layout->addWidget(tableWidget);

        // Vytvoření menu
        auto *menuBar = new QMenuBar(this);
        auto *fileMenu = menuBar->addMenu("&Soubor");
        auto *helpMenu = menuBar->addMenu("&Nápověda");

        // Přidání akcí do menu
        auto *exitAction = new QAction("&Konec", this);
        fileMenu->addAction(exitAction);
        connect(exitAction, &QAction::triggered, qApp, &QApplication::quit);

        auto *aboutAction = new QAction("&O aplikaci", this);
        helpMenu->addAction(aboutAction);
        connect(aboutAction, &QAction::triggered, this, &Spreadsheet::showAboutDialog);

        layout->setMenuBar(menuBar);
    }

private slots:
    void showAboutDialog() {
        QMessageBox::about(this, "O aplikaci", "Jednoduchý tabulkový editor v Qt.");
    }

private:
    QTableWidget *tableWidget;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    Spreadsheet spreadsheet;
    spreadsheet.setWindowTitle("Tabulkový Editor");
    spreadsheet.resize(800, 600);
    spreadsheet.show();

    return app.exec();
}
