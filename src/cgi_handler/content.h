#ifndef PEAKS_CONTENT_H_
#define PEAKS_CONTENT_H_

#include <cppcms/view.h>
#include <cppcms/form.h>
#include <string>

namespace peaks{
namespace pks{
namespace content  {
    struct certificate : public cppcms::base_content {
        std::string keyID;
        std::string pubkey;
    };
    struct index : public cppcms::base_content {
        std::string searchString;
        std::string results;
    };
    struct vindex : public cppcms::base_content {
        std::string searchString;
        std::string key_component;
    };
    struct submit_form : public cppcms::form {
        cppcms::widgets::textarea keytext;
        cppcms::widgets::submit reset;
        cppcms::widgets::submit submit;

        submit_form() {
            keytext.rows(20);
            keytext.cols(66);
            reset.value("Clear");
            submit.value("Submit this key to the keyserver!");

            add(keytext);
            add(reset);
            add(submit);
        }
    };
    struct remove_form : public cppcms::form {
        cppcms::widgets::textarea verification;
        cppcms::widgets::text keyid;
        cppcms::widgets::submit remove;

        remove_form() {
            verification.rows(20);
            verification.cols(66);
            remove.value("Remove the key!");

            add(verification);
            add(keyid);
            add(remove);
        }
    };
    struct homepage : public cppcms::base_content {
        submit_form submit;
        remove_form remove;
    };
    struct stats : public cppcms::base_content{
    };


};

}
}
#endif // PEAKS_CONTENT_H_
