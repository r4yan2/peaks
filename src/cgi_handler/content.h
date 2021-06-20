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
        cppcms::widgets::text search;
        cppcms::widgets::submit submit;

        remove_form() {
            submit.value("Remove the key!");

            add(search);
            add(submit);
        }
    };
    struct homepage : public cppcms::base_content {
        submit_form submit;
        remove_form remove;
    };

};

}
}
#endif // PEAKS_CONTENT_H_
