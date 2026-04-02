class Dialog {
 public:
  virtual ~Dialog();
};
class BaseDialog : public Dialog {};
class AboutDialog : public BaseDialog {
 protected:
  virtual void Draw();
};
class UnsafeBase {
 public:
  virtual void Draw();
};
