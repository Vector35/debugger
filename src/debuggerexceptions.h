class ConnectionRefusedError: public std::exception
{
    std::string m_error;

    public:
        ConnectionRefusedError(const std::string& error): std::exception(), m_error(error) {}
#ifdef __GNUC__
        virtual const char* what() const noexcept { return m_error.c_str(); }
#else
        virtual const char* what() const { return m_error.c_str(); }
#endif
};


class ProcessStartError: public std::exception
{
    std::string m_error;

    public:
        ProcessStartError(const std::string& error): std::exception(), m_error(error) {}
#ifdef __GNUC__
        virtual const char* what() const noexcept { return m_error.c_str(); }
#else
        virtual const char* what() const { return m_error.c_str(); }
#endif
};


class NotExecutableError: public std::exception
{
    std::string m_error;

    public:
        NotExecutableError(const std::string& error): std::exception(), m_error(error) {}
#ifdef __GNUC__
        virtual const char* what() const noexcept { return m_error.c_str(); }
#else
        virtual const char* what() const { return m_error.c_str(); }
#endif
};


class NotInstalledError: public std::exception
{
    std::string m_error;

    public:
        NotInstalledError(const std::string& error): std::exception(), m_error(error) {}
#ifdef __GNUC__
        virtual const char* what() const noexcept { return m_error.c_str(); }
#else
        virtual const char* what() const { return m_error.c_str(); }
#endif
};


class PermissionDeniedError: public std::exception
{
    std::string m_error;

    public:
        PermissionDeniedError(const std::string& error): std::exception(), m_error(error) {}
#ifdef __GNUC__
        virtual const char* what() const noexcept { return m_error.c_str(); }
#else
        virtual const char* what() const { return m_error.c_str(); }
#endif
};
