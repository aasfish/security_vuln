from app import app
import ssl

if __name__ == "__main__":
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('certs/server.crt', 'certs/server.key')

    # Run with SSL on port 5000
    app.run(host="0.0.0.0", port=5000, ssl_context=context, debug=True)