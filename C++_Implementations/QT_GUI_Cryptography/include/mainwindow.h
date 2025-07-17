#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "RSAKeyGeneration.hpp"
#include "CreateHashDigest.hpp"
#include "AES_ECB.hpp"
#include "AES_CBC.hpp"
#include "AES_CFB.hpp"
#include "AES_OFB.hpp"
#include "AES_CTR.hpp"
#include "AES_GCM.hpp"
#include "SHA3.hpp"
#include "ECDSA.hpp"
#include <QMainWindow>
#include <string.h>
#include <chrono>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    /// @brief This method instantiates the main window 
    /// @param parent optional - The pointer to the QWidget that is this windows parent if one exists, default is nullptr
    MainWindow(QWidget *parent = nullptr);

    /// @brief This method destructs the main window
    ~MainWindow();

private slots:
    
    /// @brief This method generates RSA Keys when the 'Generate' button is clicked
    void on_generate_button_clicked();

    /// @brief This method encrypts the inputted hexadecimal string when the 'Encrypt' button is clicked
    void on_encrypt_button_clicked();

    /// @brief This method decrypts the inputted hexadecimal string when the 'Decrypt' button is clicked
    void on_decrypt_button_clicked();

    /// @brief This method generates the hash digests when the 'Hash' button is clicked
    void on_hash_button_clicked();

    /// @brief This method moved the text from the output text box to the input text box when the button is clicked
    void on_rsa_swap_output_button_clicked();

    void on_aes_swap_output_button_clicked();

    void on_aes_key_gen_clicked();

    void on_aes_iv_gen_clicked();
    
    void on_aes_encrypt_clicked();

    void on_aes_decrypt_clicked();

    void on_ecdsa_key_gen_clicked();

    void on_ecdsa_curve_selected();

    void on_ecdsa_calc_pub_key_clicked();

    void on_ecdsa_sig_gen_clicked();

    void on_ecdsa_sig_ver_clicked();

private:
    /// @brief This variable holds the instantiated key generation object to be used
    RSAKeyGeneration key_gen_;

    /// @brief This variable holds the current RSA keys
    RSAKeyGenerationResult rsa_keys_;

    /// @brief This method updated the key length for the key_gen_ based on user selections from the drop down
    void updateKeyLength();

    string getRandom(int bits);

    int getSelectedBits();

    ECDSA getSelectedECDSACurve();

    WeirrstrassCurve getSelectedECDSAWeirrstrassCurve();

    bool aes_is_padded;

    QString removePadding(QString aes_out);

    QString getInputAndPad();

    std::string addSpacing(std::string input);

    /// @brief This method generated the rsa keys based on the information from the dropdowns such as key length and prime generation method.
    /// @param use_key_quintuple_form Whether the private key being generated should be in quintuple form
    /// @return The duration that the key generation took to run
    double generateKeys(bool use_key_quintuple_form);

    /// @brief The main UI object for the window
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
